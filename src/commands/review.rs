// unfault-ignore: rust.println_in_lib
//! # Review Command
//!
//! Implements the code review/analysis command for the Unfault CLI.
//!
//! ## Architecture
//!
//! The review command uses **client-side parsing**:
//! 1. Parse source files locally using tree-sitter (via unfault-core)
//! 2. Build an Intermediate Representation (IR) containing semantics and code graph
//! 3. Send serialized IR to the API (no source code over the wire)
//! 4. Receive findings and optionally preview patches locally
//!
//! ## Usage
//!
//! ```bash
//! unfault review               # Analyze current directory
//! unfault review --dry-run     # Show what fixes would be applied
//! unfault review --output full
//! unfault review --output json
//! unfault review --output sarif
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::api::graph::IrFinding;
use crate::api::{ApiClient, ApiError};
use crate::config::Config;
use crate::errors::{
    display_auth_error, display_config_error, display_network_error, display_service_error,
    display_validation_error,
};
use crate::exit_codes::*;
use crate::session::{
    MetaFileInfo, PatchApplier, ScanProgress, WorkspaceScanner, build_ir_cached,
    extract_package_export, get_git_remote, get_or_compute_workspace_id,
};

/// Get uncommitted files from git (staged, unstaged, and untracked).
///
/// Returns a list of relative paths for files that have uncommitted changes.
/// Returns None if the directory is not a git repository.
fn get_uncommitted_files(dir: &std::path::Path) -> Option<Vec<String>> {
    use std::process::Command;

    // Check if this is a git repo
    let is_git = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(dir)
        .output()
        .ok()
        .is_some_and(|o| o.status.success());

    if !is_git {
        return None;
    }

    let mut files = std::collections::HashSet::new();

    // Unstaged modified files
    if let Ok(output) = Command::new("git")
        .args(["diff", "--name-only"])
        .current_dir(dir)
        .output()
    {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if !line.is_empty() {
                    files.insert(line.to_string());
                }
            }
        }
    }

    // Staged files
    if let Ok(output) = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(dir)
        .output()
    {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if !line.is_empty() {
                    files.insert(line.to_string());
                }
            }
        }
    }

    // Untracked files (new files not yet added)
    if let Ok(output) = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(dir)
        .output()
    {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if !line.is_empty() {
                    files.insert(line.to_string());
                }
            }
        }
    }

    Some(files.into_iter().collect())
}

/// Handle an API error and return the appropriate exit code.
fn handle_api_error(error: ApiError) -> i32 {
    match error {
        ApiError::Unauthorized { message } => {
            display_auth_error(&message);
            EXIT_AUTH_ERROR
        }
        ApiError::Forbidden { message } => {
            display_auth_error(&message);
            EXIT_AUTH_ERROR
        }
        ApiError::Network { message } => {
            display_network_error(&message);
            EXIT_NETWORK_ERROR
        }
        ApiError::Server { status, message } => {
            display_service_error(&format!("HTTP {} - {}", status, message));
            EXIT_NETWORK_ERROR
        }
        ApiError::ClientError { status, message } => {
            display_network_error(&format!("HTTP {} - {}", status, message));
            EXIT_NETWORK_ERROR
        }
        ApiError::ValidationError { message } => {
            display_validation_error(&message);
            EXIT_CONFIG_ERROR
        }
        ApiError::ParseError { message } => {
            display_network_error(&message);
            EXIT_NETWORK_ERROR
        }
    }
}

/// Arguments for the review command
pub struct ReviewArgs {
    /// Output format (text, json, sarif, or llm)
    pub output_format: String,
    /// Output mode (concise or full)
    pub output_mode: String,
    /// Verbose mode (dump raw responses)
    pub verbose: bool,
    /// Override the detected profile
    pub profile: Option<String>,
    /// Dimensions to analyze (None = all from profile)
    pub dimensions: Option<Vec<String>>,
    /// Show what fixes would be applied without actually applying them
    pub dry_run: bool,
    /// Print raw findings instead of hotspot summary
    pub raw_findings: bool,
    /// Include test files in analysis (default: skip tests)
    pub include_tests: bool,
    /// Discover SLOs from observability platforms (GCP, Datadog, Dynatrace)
    pub discover_observability: bool,
    /// Limit number of findings in LLM output (default 50, max 200)
    pub top: Option<usize>,
    /// Restrict analysis to specific files
    pub files: Option<Vec<String>>,
    /// Review only uncommitted files (staged, unstaged, and untracked)
    pub uncommitted: bool,
}

/// Stats from SLO discovery for display in review summary.
#[derive(Default, Clone)]
struct SloDiscoveryStats {
    /// Number of SLOs discovered
    slo_count: usize,
    /// Number of routes linked to at least one SLO
    monitored_routes: usize,
    /// Total number of HTTP routes in the codebase
    total_routes: usize,
    /// Whether discovery was attempted
    attempted: bool,
    /// Whether credentials expired (need re-auth)
    credentials_expired: bool,
    /// Whether no provider credentials were found
    no_credentials: bool,
}

/// Display SLO coverage summary with positive feedback.
fn display_slo_summary(stats: &SloDiscoveryStats) {
    if !stats.attempted {
        return;
    }

    eprintln!();
    eprintln!("{}", "─".repeat(60).dimmed());

    // Handle credential issues first
    if stats.credentials_expired {
        eprintln!(
            "{} {} Your GCP credentials have expired.",
            "📊".cyan(),
            "Observability:".bold()
        );
        eprintln!();
        eprintln!(
            "   {} Run {} to refresh them.",
            "→".cyan(),
            "gcloud auth application-default login".bright_yellow()
        );
        eprintln!(
            "   {}",
            "Once refreshed, SLO discovery will link your routes to your monitoring.".dimmed()
        );
        return;
    }

    if stats.no_credentials {
        eprintln!(
            "{} {} No observability provider credentials found.",
            "📊".cyan(),
            "Observability:".bold()
        );
        eprintln!();
        eprintln!("   {}", "To discover SLOs, configure one of:".dimmed());
        eprintln!(
            "   {} GCP: {}",
            "•".dimmed(),
            "gcloud auth application-default login".bright_yellow()
        );
        eprintln!(
            "   {} Datadog: set {}",
            "•".dimmed(),
            "DD_API_KEY".bright_yellow()
        );
        eprintln!(
            "   {} Dynatrace: set {}",
            "•".dimmed(),
            "DT_API_TOKEN".bright_yellow()
        );
        return;
    }

    if stats.slo_count == 0 {
        // No SLOs found (but credentials were valid)
        eprintln!(
            "{} {} No SLOs discovered from your observability provider.",
            "📊".cyan(),
            "Observability:".bold()
        );
        eprintln!(
            "   {}",
            "Consider setting up SLOs to track how users experience your service.".dimmed()
        );
        return;
    }

    // SLOs were found - show coverage
    let coverage_percent = if stats.total_routes > 0 {
        (stats.monitored_routes as f64 / stats.total_routes as f64 * 100.0).round() as i32
    } else {
        0
    };

    eprintln!(
        "{} {} {} SLO(s) linked to {}/{} routes ({}% coverage)",
        "📊".cyan(),
        "Observability:".bold(),
        stats.slo_count,
        stats.monitored_routes,
        stats.total_routes,
        coverage_percent
    );

    if stats.total_routes > 0 && stats.monitored_routes == stats.total_routes {
        // Full coverage - celebrate!
        eprintln!();
        eprintln!(
            "   {} {}",
            "✓".green().bold(),
            "All your HTTP routes are covered by SLOs.".green()
        );
        eprintln!(
            "   {}",
            "This gives you visibility into how users are experiencing your service.".dimmed()
        );
    } else if stats.monitored_routes > 0 {
        // Partial coverage
        let unmonitored = stats.total_routes - stats.monitored_routes;
        eprintln!();
        eprintln!(
            "   {} {} route(s) are not covered by any SLO.",
            "⚠".yellow(),
            unmonitored
        );
        eprintln!(
            "   {}",
            "Consider adding SLOs for these routes to ensure full observability.".dimmed()
        );
    } else if stats.total_routes > 0 {
        // No routes linked despite having SLOs
        eprintln!();
        eprintln!(
            "   {} Your SLOs don't have path patterns that match your routes.",
            "ℹ".blue()
        );
        eprintln!(
            "   {}",
            "Run with --verbose to see SLO details, or configure service-level SLOs.".dimmed()
        );
    }
}

/// Execute the review command
///
/// Analyzes the current directory and displays findings.
///
/// # Arguments
///
/// * `args` - Review command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Analysis completed with no findings
/// * `Ok(EXIT_FINDINGS_FOUND)` - Analysis completed with findings
/// * `Ok(EXIT_CONFIG_ERROR)` - Configuration error
/// * `Ok(EXIT_AUTH_ERROR)` - Authentication error
/// * `Ok(EXIT_NETWORK_ERROR)` - Network error
/// State for progressive display during scanning.
struct ScanDisplayState {
    workspace_label: String,
    languages: Vec<String>,
    frameworks: Vec<String>,
    file_count: usize,
    lines_printed: usize,
}

impl ScanDisplayState {
    fn new(workspace_label: String) -> Self {
        Self {
            workspace_label,
            languages: Vec::new(),
            frameworks: Vec::new(),
            file_count: 0,
            lines_printed: 0,
        }
    }

    /// Update the display with new progress.
    fn update(&mut self, progress: &ScanProgress) {
        self.file_count = progress.file_count;
        self.languages = progress.languages.clone();
        self.frameworks = progress.frameworks.clone();
    }

    /// Render the current state to the terminal, overwriting previous lines.
    fn render(&mut self, dimensions: &[String], profile_override: Option<&str>) {
        // Move cursor up to overwrite previous lines
        if self.lines_printed > 0 {
            // Move up and clear each line
            for _ in 0..self.lines_printed {
                eprint!("\x1b[1A\x1b[2K");
            }
        }

        let mut lines = 0;

        // Header line with workspace name
        eprintln!(
            "{} Analyzing {}...",
            "→".cyan().bold(),
            self.workspace_label.bright_blue()
        );
        lines += 1;

        // Languages line
        if !self.languages.is_empty() {
            eprintln!("  Languages: {}", self.languages.join(", ").cyan());
            lines += 1;
        }

        // Frameworks line
        if !self.frameworks.is_empty() {
            eprintln!("  Frameworks: {}", self.frameworks.join(", ").cyan());
            lines += 1;
        }

        // Profile override line
        if let Some(profile) = profile_override {
            eprintln!("  Profile: {} (override)", profile.cyan());
            lines += 1;
        }

        // Dimensions line
        eprintln!(
            "  Dimensions: {}",
            format_list_dimmed(dimensions, ", ").cyan()
        );
        lines += 1;

        // File count line (always show, even if 0)
        let file_word = if self.file_count == 1 {
            "file"
        } else {
            "files"
        };
        eprintln!(
            "  Found {} matching source {}",
            self.file_count.to_string().bright_green(),
            file_word
        );
        lines += 1;

        self.lines_printed = lines;
        let _ = io::stderr().flush();
    }

    fn clear(&mut self) {
        if self.lines_printed == 0 {
            return;
        }
        for _ in 0..self.lines_printed {
            eprint!("\x1b[1A\x1b[2K");
        }
        self.lines_printed = 0;
        let _ = io::stderr().flush();
    }
}

fn format_list_dimmed(values: &[String], separator: &str) -> String {
    if values.is_empty() {
        "—".into()
    } else {
        values.join(separator)
    }
}

pub async fn execute(args: ReviewArgs) -> Result<i32> {
    // Load configuration
    let mut config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            display_config_error(&format!("{}", e));
            eprintln!(
                "\n{} Run `unfault login` to authenticate first.",
                "Tip:".cyan().bold()
            );
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Create API client (env var takes precedence over config file)
    let api_client = ApiClient::new(config.base_url());
    let trace_id = api_client.trace_id.clone();

    // Get current directory
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;

    // Resolve file filter from --file and/or --uncommitted flags
    let filter_paths: Option<Vec<String>> = if args.uncommitted {
        match get_uncommitted_files(&current_dir) {
            Some(files) if files.is_empty() => {
                eprintln!(
                    "{} No uncommitted files found. Working tree is clean.",
                    "✓".green().bold()
                );
                return Ok(EXIT_SUCCESS);
            }
            Some(files) => {
                // Merge with explicit --file args if any
                let mut all_files: std::collections::HashSet<String> = files.into_iter().collect();
                if let Some(ref explicit) = args.files {
                    for f in explicit {
                        all_files.insert(f.clone());
                    }
                }
                Some(all_files.into_iter().collect())
            }
            None => {
                eprintln!(
                    "{} Not a git repository. --uncommitted requires git.",
                    "✗".red().bold()
                );
                return Ok(EXIT_CONFIG_ERROR);
            }
        }
    } else {
        args.files.clone()
    };

    // Start timing the session
    let session_start = Instant::now();

    // Get workspace label first (just the directory name)
    let workspace_label = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace")
        .to_string();

    // Determine dimensions to analyze (needed for display)
    let dimensions: Vec<String> = args.dimensions.clone().unwrap_or_else(|| {
        vec![
            "stability".to_string(),
            "correctness".to_string(),
            "performance".to_string(),
        ]
    });

    // Set up progressive display state
    let display_state = Arc::new(Mutex::new(ScanDisplayState::new(workspace_label.clone())));
    let display_state_clone = Arc::clone(&display_state);
    let dimensions_clone = dimensions.clone();
    let profile_clone = args.profile.clone();

    // Initial render with 0 files
    {
        let mut state = display_state.lock().unwrap();
        state.render(&dimensions, args.profile.as_deref());
    }

    // Step 1: Scan workspace with progress callback
    let mut scanner = WorkspaceScanner::new(&current_dir).with_progress(move |progress| {
        let mut state = display_state_clone.lock().unwrap();
        state.update(&progress);
        state.render(&dimensions_clone, profile_clone.as_deref());
    });

    let workspace_info = scanner.scan().context("Failed to scan workspace")?;

    // Final render with complete info
    {
        let mut state = display_state.lock().unwrap();
        state.file_count = if args.include_tests {
            workspace_info.source_files.len()
        } else {
            workspace_info
                .source_files
                .iter()
                .filter(|(p, _)| {
                    let rel = p.strip_prefix(&current_dir).unwrap_or(p).to_string_lossy();
                    !is_test_path(&rel)
                })
                .count()
        };
        state.languages = workspace_info.language_strings();
        state.frameworks = workspace_info.framework_strings();
        state.render(&dimensions, args.profile.as_deref());
        state.clear();
    }

    if workspace_info.source_files.is_empty() {
        eprintln!(
            "{} No source files found in the current directory.",
            "⚠".yellow().bold()
        );
        return Ok(EXIT_SUCCESS);
    }

    // Client-side parsing
    execute_client_parse(
        &args,
        &mut config,
        &api_client,
        &trace_id,
        &current_dir,
        &workspace_label,
        &dimensions,
        &workspace_info,
        session_start,
        filter_paths.as_ref(),
    )
    .await
}

/// Execute review with client-side parsing (default mode).
///
/// 1. Parse source files locally using tree-sitter
/// 2. Build IR (semantics + graph)
/// 3. Ingest graph to API (chunked, resumable)
/// 4. Stream semantics in chunks to API for rule evaluation
/// 5. Fetch findings and optionally apply patches
#[allow(clippy::too_many_arguments)]
fn is_test_path(path: &str) -> bool {
    let lower = path.to_lowercase().replace('\\', "/");

    lower.starts_with("test/")
        || lower.starts_with("tests/")
        || lower.starts_with("testdata/")
        || lower.starts_with("fixtures/")
        || lower.contains("/test/")
        || lower.contains("/tests/")
        || lower.contains("/testdata/")
        || lower.contains("/fixtures/")
        || lower.contains("/__tests__/")
        || lower.contains("_test.")
        || lower.contains(".test.")
        || lower.contains(".spec.")
        || lower.ends_with("_test.go")
        || lower.ends_with("_test.rs")
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.ts")
        || lower.ends_with("_test.tsx")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.tsx")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.tsx")
        || lower
            .split('/')
            .next_back()
            .is_some_and(|name| name.starts_with("test_") || name.starts_with("spec_"))
}

#[allow(clippy::too_many_arguments)]
async fn execute_client_parse(
    args: &ReviewArgs,
    config: &mut Config,
    api_client: &ApiClient,
    trace_id: &str,
    current_dir: &std::path::Path,
    workspace_label: &str,
    dimensions: &[String],
    workspace_info: &crate::session::WorkspaceInfo,
    session_start: Instant,
    filter_paths: Option<&Vec<String>>,
) -> Result<i32> {
    use crate::api::SemanticsChunker;

    // Create progress bar for operations
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    // Step 1: Build IR locally (with caching)
    pb.set_message("Parsing source files locally...");

    let parse_start = Instant::now();

    // Build set of paths to filter findings (from --file or --uncommitted)
    // These are relative paths that will be matched against finding file_path
    let finding_filter: Option<std::collections::HashSet<String>> = filter_paths.map(|files| {
        files
            .iter()
            .map(|f| {
                // Normalize to relative path from workspace root
                let p = PathBuf::from(f);
                if p.is_absolute() {
                    p.strip_prefix(current_dir)
                        .map(|rel| rel.to_string_lossy().to_string())
                        .unwrap_or_else(|_| f.clone())
                } else {
                    f.clone()
                }
            })
            .collect()
    });

    // Exclude test files from parsing (unless --include-tests).
    // We always parse ALL non-test files to maintain full workspace context.
    // Findings are filtered later by finding_filter.
    let file_paths: Option<Vec<std::path::PathBuf>> = if args.include_tests {
        None
    } else {
        Some(
            workspace_info
                .source_files
                .iter()
                .filter_map(|(p, _)| {
                    let rel = p.strip_prefix(current_dir).unwrap_or(p).to_string_lossy();
                    if is_test_path(&rel) {
                        None
                    } else {
                        Some(p.clone())
                    }
                })
                .collect(),
        )
    };

    let build_result = match build_ir_cached(current_dir, file_paths.as_deref(), args.verbose, None)
    {
        Ok(result) => result,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("{} Failed to parse source files: {}", "✗".red().bold(), e);
            return Ok(EXIT_CONFIG_ERROR);
        }
    };
    let parse_ms = parse_start.elapsed().as_millis() as u64;

    let ir = build_result.ir;
    let cache_stats = build_result.cache_stats;
    let file_count = ir.file_count();

    if args.verbose {
        let stats = ir.graph.stats();
        eprintln!(
            "\n{} Built IR: {} files, {} functions, {} imports ({}ms)",
            "DEBUG".yellow(),
            stats.file_count,
            stats.function_count,
            stats.import_edge_count,
            parse_ms
        );
        eprintln!(
            "{} Cache: {} hits, {} misses ({:.1}% hit rate)",
            "DEBUG".yellow(),
            cache_stats.hits,
            cache_stats.misses,
            cache_stats.hit_rate()
        );
    }

    // Split IR into components so we can free memory early
    let unfault_core::IntermediateRepresentation {
        semantics,
        mut graph,
    } = ir;

    // Extract package export info for cross-workspace dependency tracking
    let meta_files: Vec<MetaFileInfo> = workspace_info
        .meta_files
        .iter()
        .map(|mf| MetaFileInfo {
            kind: mf.kind.as_str(),
            contents: mf.contents.clone(),
        })
        .collect();
    let package_export = extract_package_export(&meta_files);

    // Step 2: Compute workspace ID (with persistent mapping)
    // Use git remote first, then manifest files (pyproject.toml, etc.), then fallback to label
    // This must match the workspace ID computation in `ask` command for consistency
    let git_remote = get_git_remote(current_dir);
    let workspace_id_result = get_or_compute_workspace_id(
        current_dir,
        git_remote.as_deref(),
        if meta_files.is_empty() {
            None
        } else {
            Some(&meta_files)
        },
        Some(workspace_label),
    );
    let workspace_id = workspace_id_result
        .as_ref()
        .map(|r| r.id.clone())
        .unwrap_or_else(|| format!("wks_{}", uuid::Uuid::new_v4().simple()));

    // Step 2.5: Discover and link SLOs (if --discover-observability flag is set)
    let mut slo_stats = SloDiscoveryStats::default();

    if args.discover_observability {
        use crate::slo::{
            SloEnricher, get_service_display_name, get_service_level_slos, group_slos_by_service,
        };
        use std::io::{self, Write};

        slo_stats.attempted = true;

        // Count total HTTP routes before linking
        slo_stats.total_routes = graph
            .function_nodes
            .values()
            .filter(|&node_idx| {
                if let Some(node) = graph.graph.node_weight(*node_idx) {
                    node.http_method().is_some()
                } else {
                    false
                }
            })
            .count();

        let enricher = SloEnricher::new(args.verbose);
        if enricher.any_provider_available() {
            let providers = enricher.available_providers();
            pb.set_message(format!("Discovering SLOs from {}...", providers.join(", ")));

            match enricher.fetch_all().await {
                Ok(fetch_result) => {
                    // Track credential issues from the fetch
                    if fetch_result.credentials_expired {
                        slo_stats.credentials_expired = true;
                    }

                    let slos = fetch_result.slos;
                    if !slos.is_empty() {
                        // First, link SLOs that have path patterns (automatic matching)
                        let linked = enricher.enrich_graph(&mut graph, &slos).unwrap_or(0);

                        // Check for service-level SLOs (no path pattern)
                        let service_slos = get_service_level_slos(&slos);

                        if !service_slos.is_empty() {
                            // Check if we have a stored mapping for this workspace
                            let stored_service =
                                config.get_workspace_service(&workspace_id).cloned();

                            if let Some(ref service_name) = stored_service {
                                // Use stored mapping - link all SLOs for that service
                                pb.suspend(|| {
                                    if args.verbose {
                                        eprintln!(
                                            "\n{} Using saved service mapping: {}",
                                            "DEBUG".yellow(),
                                            get_service_display_name(service_name)
                                        );
                                    }
                                });

                                let grouped = group_slos_by_service(&slos);
                                if let Some(service_slos) = grouped.get(service_name) {
                                    for slo in service_slos {
                                        enricher.link_service_slo_to_all_routes(&mut graph, slo);
                                    }
                                }
                            } else {
                                // No stored mapping - prompt user
                                let grouped = group_slos_by_service(&slos);

                                if !grouped.is_empty() {
                                    // Finish the progress bar before prompting
                                    pb.finish_and_clear();

                                    eprintln!();
                                    eprintln!(
                                        "We found SLOs in your GCP project that apply to entire services."
                                    );
                                    eprintln!("Which service does this codebase deploy to?");
                                    eprintln!();

                                    let services: Vec<_> = grouped.keys().collect();
                                    for (i, service_name) in services.iter().enumerate() {
                                        let display_name = get_service_display_name(service_name);
                                        eprintln!("  [{}] {}", i + 1, display_name.cyan());

                                        // Show SLOs for this service
                                        if let Some(slos) = grouped.get(*service_name) {
                                            for slo in slos {
                                                let status = if let Some(budget) =
                                                    slo.error_budget_remaining
                                                {
                                                    if budget < 20.0 {
                                                        format!("{:.0}% budget remaining", budget)
                                                            .yellow()
                                                            .to_string()
                                                    } else {
                                                        "healthy".green().to_string()
                                                    }
                                                } else {
                                                    "".to_string()
                                                };
                                                eprintln!(
                                                    "      └─ {:.0}% {} {}",
                                                    slo.target_percent,
                                                    slo.name.dimmed(),
                                                    status
                                                );
                                            }
                                        }
                                    }
                                    eprintln!("  [s] Skip (don't link SLOs)");
                                    eprintln!();
                                    eprint!("> ");
                                    io::stderr().flush().ok();

                                    // Read user input
                                    let mut input = String::new();
                                    if io::stdin().read_line(&mut input).is_ok() {
                                        let input = input.trim().to_lowercase();

                                        if input != "s" && input != "skip" {
                                            if let Ok(choice) = input.parse::<usize>() {
                                                if choice > 0 && choice <= services.len() {
                                                    let selected_service =
                                                        services[choice - 1].clone();

                                                    // Link all SLOs for this service
                                                    if let Some(slos_to_link) =
                                                        grouped.get(&selected_service)
                                                    {
                                                        let route_count =
                                                            graph.get_http_route_handlers().len();
                                                        for slo in slos_to_link {
                                                            enricher
                                                                .link_service_slo_to_all_routes(
                                                                    &mut graph, slo,
                                                                );
                                                        }

                                                        eprintln!(
                                                            "\n{} Linked {} SLO(s) to {} route handler(s).",
                                                            "✓".green().bold(),
                                                            slos_to_link.len(),
                                                            route_count
                                                        );
                                                    }

                                                    // Save the mapping
                                                    config.set_workspace_service(
                                                        workspace_id.clone(),
                                                        selected_service.clone(),
                                                    );
                                                    if let Err(e) = config.save() {
                                                        if args.verbose {
                                                            eprintln!(
                                                                "{} Failed to save config: {}",
                                                                "DEBUG".yellow(),
                                                                e
                                                            );
                                                        }
                                                    } else {
                                                        eprintln!(
                                                            "  {}",
                                                            "(Saved to config, won't ask again for this workspace)".dimmed()
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Recreate progress bar for remaining steps
                                    pb.reset();
                                    pb.set_message("Uploading code graph... 0%");
                                }
                            }
                        }

                        // Update SLO stats after all linking is complete
                        slo_stats.slo_count = graph.slo_nodes.len();
                        // Count routes that have at least one MONITORED_BY edge
                        slo_stats.monitored_routes = graph
                            .function_nodes
                            .values()
                            .filter(|&node_idx| {
                                // Only count HTTP routes (have http_method)
                                let is_route = graph
                                    .graph
                                    .node_weight(*node_idx)
                                    .is_some_and(|n| n.http_method().is_some());
                                if !is_route {
                                    return false;
                                }
                                // Check if this route has a MonitoredBy edge
                                graph.graph.edges(*node_idx).any(|edge| {
                                    matches!(
                                        edge.weight(),
                                        unfault_core::graph::GraphEdgeKind::MonitoredBy
                                    )
                                })
                            })
                            .count();

                        if args.verbose {
                            eprintln!(
                                "\n{} Discovered {} SLO(s), linked {} via path patterns",
                                "DEBUG".yellow(),
                                slos.len(),
                                linked
                            );
                            for slo in &slos {
                                let budget_info = slo
                                    .error_budget_remaining
                                    .map(|b| format!(", budget: {:.1}%", b))
                                    .unwrap_or_default();
                                let current_info = slo
                                    .current_percent
                                    .map(|c| format!(" (current: {:.2}%)", c))
                                    .unwrap_or_default();
                                eprintln!(
                                    "  {} {} [{}]: target {:.2}%{}{}",
                                    "→".cyan(),
                                    slo.name,
                                    slo.provider,
                                    slo.target_percent,
                                    current_info,
                                    budget_info
                                );
                                if let Some(ref pattern) = slo.path_pattern {
                                    eprintln!("    path pattern: {}", pattern.dimmed());
                                }
                            }
                        }
                    } else if args.verbose {
                        eprintln!(
                            "\n{} No SLOs found from providers (check that SLOs exist and have URL/path metadata)",
                            "DEBUG".yellow()
                        );
                    }
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    // Track auth errors for summary display
                    if error_msg.contains("gcloud auth") || error_msg.contains("expired") {
                        slo_stats.credentials_expired = true;
                    }
                    if args.verbose {
                        eprintln!("\n{} SLO discovery failed: {}", "DEBUG".yellow(), e);
                    }
                }
            }
        } else {
            slo_stats.no_credentials = true;
            if args.verbose {
                eprintln!(
                    "\n{} No SLO provider credentials found (checked: DD_API_KEY, GCP ADC, DT_API_TOKEN)",
                    "DEBUG".yellow()
                );
            }
        }
    }

    // Precompute SLO definitions for LLM output before graph ingest (graph is moved).
    let slo_definitions_llm: Option<Vec<LlmSloDefinition>> = if args.discover_observability {
        let mut slos: Vec<LlmSloDefinition> = Vec::new();
        for idx in graph.slo_nodes.values() {
            if let Some(unfault_core::graph::GraphNode::Slo {
                id,
                name,
                provider,
                path_pattern,
                http_method,
                target_percent,
                current_percent,
                error_budget_remaining,
                timeframe,
                dashboard_url,
            }) = graph.graph.node_weight(*idx)
            {
                let mut monitored_routes = graph
                    .routes_for_slo(*idx)
                    .into_iter()
                    .filter_map(|route_idx| graph.get_route_info(route_idx).map(|r| r.2))
                    .collect::<Vec<_>>();
                monitored_routes.sort();
                monitored_routes.dedup();
                let monitored_route_count = monitored_routes.len();
                monitored_routes.truncate(50);

                slos.push(LlmSloDefinition {
                    id: id.clone(),
                    name: name.clone(),
                    provider: format!("{:?}", provider),
                    path_pattern: Some(path_pattern.clone()).filter(|p| !p.is_empty() && p != "*"),
                    http_method: http_method.clone(),
                    target_percent: *target_percent,
                    current_percent: *current_percent,
                    error_budget_remaining: *error_budget_remaining,
                    timeframe: timeframe.clone(),
                    dashboard_url: dashboard_url.clone(),
                    monitored_route_count,
                    monitored_routes,
                });
            }
        }
        if slos.is_empty() {
            None
        } else {
            slos.sort_by(|a, b| a.name.cmp(&b.name));
            Some(slos)
        }
    } else {
        None
    };

    // Step 3: Ingest full graph to API (streaming, compressed)
    pb.set_message("Uploading code graph... 0%");

    if args.verbose {
        eprintln!(
            "\n{} Graph stats before upload: {} SLO nodes, {} total nodes, {} edges",
            "DEBUG".yellow(),
            graph.slo_nodes.len(),
            graph.graph.node_count(),
            graph.graph.edge_count()
        );
    }

    let ingest_start = Instant::now();
    let pb_upload = pb.clone();
    let ingest = match api_client
        .ingest_graph_with_progress(
            &config.api_key,
            &workspace_id,
            Some(workspace_label),
            git_remote.as_deref(),
            package_export.as_ref(),
            graph,
            move |progress| {
                pb_upload.set_message(format!("Uploading code graph... {}%", progress.percent));
            },
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };

    if args.verbose {
        eprintln!(
            "\n{} Graph ingested: {} nodes, {} edges ({}ms)",
            "DEBUG".yellow(),
            ingest.nodes_created,
            ingest.edges_created,
            ingest_start.elapsed().as_millis()
        );
        eprintln!("{} Session ID: {}", "DEBUG".yellow(), ingest.session_id);
    }

    if args.verbose {
        if let Some(ref result) = workspace_id_result {
            eprintln!(
                "\n{} Workspace ID: {} (source: {:?})",
                "DEBUG".yellow(),
                result.id,
                result.source
            );
        }
    }

    // Build profiles from detected frameworks (e.g., "python_fastapi_backend", "go_gin_service")
    // The API resolves these profile IDs to specific rules
    let profiles: Vec<String> = workspace_info
        .to_workspace_descriptor()
        .profiles
        .iter()
        .map(|p| p.id.clone())
        .collect();

    if args.verbose {
        eprintln!("\n{} Detected profiles: {:?}", "DEBUG".yellow(), profiles);
    }

    // Step 4: Initialize chunked analysis
    pb.set_message("Starting analysis...");

    let api_start = Instant::now();
    let _start_resp = match api_client
        .analyze_start(&config.api_key, &ingest.session_id, &profiles)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };

    // Step 5: Stream semantics in chunks
    let mut chunker = SemanticsChunker::new(&semantics);
    let total_files = chunker.total_files();
    let mut findings_total: i64 = 0;
    let mut chunk_count: u32 = 0;

    while let Some(encoded_chunk) = chunker.next_chunk()? {
        let files_processed = chunker.files_processed();
        pb.set_message(format!(
            "Analyzing... {}/{} files (signals indexed: {})",
            files_processed, total_files, findings_total
        ));

        let chunk_resp = match api_client
            .analyze_chunk(
                &config.api_key,
                &ingest.session_id,
                chunk_count,
                encoded_chunk.data,
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                // On error, try to get status and potentially resume
                if args.verbose {
                    eprintln!(
                        "\n{} Chunk {} failed: {:?}",
                        "DEBUG".yellow(),
                        chunk_count,
                        e
                    );
                }
                pb.finish_and_clear();
                return Ok(handle_api_error(e));
            }
        };

        findings_total = chunk_resp.findings_total_so_far;
        chunk_count += 1;

        if args.verbose && encoded_chunk.is_last {
            eprintln!(
                "\n{} Sent {} chunks, {} files, {} findings",
                "DEBUG".yellow(),
                chunk_count,
                chunk_resp.files_processed_total,
                findings_total
            );
        }
    }

    // Step 6: Finalize analysis
    pb.set_message("Finalizing analysis...");

    let finalize_resp = match api_client
        .analyze_finalize(&config.api_key, &ingest.session_id)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };

    let engine_ms = api_start.elapsed().as_millis() as u64;

    if args.verbose {
        eprintln!(
            "\n{} Finalized: {} files, {} findings",
            "DEBUG".yellow(),
            finalize_resp.files_processed_total,
            finalize_resp.findings_total_so_far
        );
    }

    // Note: Embeddings for RAG (ask command) are generated lazily on first use
    // This keeps the review command fast

    // Step 7: Fetch results (hotspots by default; full findings only when needed)
    pb.set_message("Fetching results...");

    let needs_full_findings = args.dry_run
        || args.output_mode == "full"
        || args.raw_findings
        || args.output_format == "json"
        || args.output_format == "sarif"
        || args.output_format == "llm"
        || finding_filter.is_some(); // Need full findings to filter by path

    if needs_full_findings {
        let findings_resp = match api_client
            .get_session_findings(&config.api_key, &ingest.session_id)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                pb.finish_and_clear();
                return Ok(handle_api_error(e));
            }
        };

        pb.finish_and_clear();

        // Convert Finding to IrFinding for display / patching
        // Supports both new (file_path/line/column) and legacy (location) formats
        let findings: Vec<IrFinding> = findings_resp
            .findings
            .iter()
            .map(|f| {
                // Prefer new format fields, fall back to legacy location
                let (file_path, line, column, end_line, end_column) = if f.file_path.is_some() {
                    (
                        f.file_path.clone().unwrap_or_default(),
                        f.line.unwrap_or(0),
                        f.column.unwrap_or(0),
                        f.end_line,
                        f.end_column,
                    )
                } else if let Some(ref loc) = f.location {
                    (
                        loc.file.clone(),
                        loc.start_line,
                        loc.start_column.unwrap_or(0),
                        loc.end_line,
                        loc.end_column,
                    )
                } else {
                    (String::new(), 0, 0, None, None)
                };

                IrFinding {
                    rule_id: f.rule_id.clone(),
                    title: f.title.clone(),
                    description: f.description.clone(),
                    severity: f.severity.clone(),
                    dimension: f.dimension.clone(),
                    file_path,
                    line,
                    column,
                    end_line,
                    end_column,
                    message: f.description.clone(),
                    patch_json: None,
                    fix_preview: f.fix_preview.clone(),
                    patch: f.diff.clone(),
                    byte_start: None,
                    byte_end: None,
                }
            })
            .collect();

        // Filter findings by --file/--uncommitted if specified
        let findings: Vec<IrFinding> = if let Some(ref filter) = finding_filter {
            findings
                .into_iter()
                .filter(|f| filter.contains(&f.file_path))
                .collect()
        } else {
            findings
        };

        // Calculate elapsed time
        let elapsed = session_start.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;

        // Get cache hit rate for display context
        let cache_hit_rate = cache_stats.hit_rate();
        let cache_rate_opt = if cache_stats.hits > 0 || cache_stats.misses > 0 {
            Some(cache_hit_rate)
        } else {
            None
        };

        let finding_count = findings.len();

        if args.verbose {
            if finding_filter.is_some() {
                eprintln!(
                    "\n{} Analysis response: {} findings (filtered) from {} files",
                    "DEBUG".yellow(),
                    finding_count,
                    file_count
                );
            } else {
                eprintln!(
                    "\n{} Analysis response: {} findings from {} files",
                    "DEBUG".yellow(),
                    finding_count,
                    file_count
                );
            }
        }

        // Handle fix/dry-run mode
        let applied_patches = if args.dry_run {
            apply_ir_patches(args, current_dir, &findings)?
        } else {
            0
        };

        // Display results
        let display_context = ReviewOutputContext {
            workspace_label: workspace_label.to_string(),
            languages: workspace_info.language_strings(),
            frameworks: workspace_info.framework_strings(),
            dimensions: dimensions.to_vec(),
            file_count,
            elapsed_ms,
            parse_ms,
            engine_ms,
            cache_hit_rate: cache_rate_opt,
            trace_id: trace_id.chars().take(8).collect(),
            profile: args.profile.clone(),
            slo_stats: Some(slo_stats.clone()),
            slo_definitions: slo_definitions_llm.clone(),
        };

        display_ir_findings(args, &findings, applied_patches, &display_context);

        // Show SLO coverage summary if --discover-observability was used
        display_slo_summary(&slo_stats);

        if finding_count > 0 {
            Ok(EXIT_FINDINGS_FOUND)
        } else {
            Ok(EXIT_SUCCESS)
        }
    } else {
        // Default UX: insights-first, with a safe fallback to hotspots.
        let insights_resp = if args.output_mode == "basic" {
            match api_client
                .get_session_insights(&config.api_key, &ingest.session_id)
                .await
            {
                Ok(resp) => Some(resp),
                Err(ApiError::ClientError { status: 404, .. }) => None,
                Err(e) => {
                    pb.finish_and_clear();
                    return Ok(handle_api_error(e));
                }
            }
        } else {
            None
        };

        let hotspots_resp = if insights_resp.is_none() {
            Some(
                match api_client
                    .get_session_hotspots(&config.api_key, &ingest.session_id, 3, 10, 3, 3)
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        pb.finish_and_clear();
                        return Ok(handle_api_error(e));
                    }
                },
            )
        } else {
            None
        };

        pb.finish_and_clear();

        // Calculate elapsed time
        let elapsed = session_start.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;

        // Get cache hit rate for display context
        let cache_hit_rate = cache_stats.hit_rate();
        let cache_rate_opt = if cache_stats.hits > 0 || cache_stats.misses > 0 {
            Some(cache_hit_rate)
        } else {
            None
        };

        let display_context = ReviewOutputContext {
            workspace_label: workspace_label.to_string(),
            languages: workspace_info.language_strings(),
            frameworks: workspace_info.framework_strings(),
            dimensions: dimensions.to_vec(),
            file_count,
            elapsed_ms,
            parse_ms,
            engine_ms,
            cache_hit_rate: cache_rate_opt,
            trace_id: trace_id.chars().take(8).collect(),
            profile: args.profile.clone(),
            slo_stats: Some(slo_stats.clone()),
            slo_definitions: None,
        };

        let has_any = if let Some(insights) = &insights_resp {
            display_session_insights(args, insights, &display_context);
            !insights.insights.is_empty()
        } else {
            let hotspots = hotspots_resp.expect("hotspots fallback should be present");
            display_session_hotspots(args, &hotspots, &display_context);
            hotspots.hotspots.iter().any(|h| h.total_count > 0)
        };

        // Show SLO coverage summary if --discover-observability was used
        display_slo_summary(&slo_stats);

        // Footer with compact metadata and tip at the very end
        println!();
        render_session_footer(&display_context);
        println!(
            "{}",
            "Tip: use --output full to drill into hotspots.".dimmed()
        );

        if has_any {
            Ok(EXIT_FINDINGS_FOUND)
        } else {
            Ok(EXIT_SUCCESS)
        }
    }
}

/// Apply patches from IR findings to local files.
fn apply_ir_patches(
    args: &ReviewArgs,
    workspace_path: &std::path::Path,
    findings: &[IrFinding],
) -> Result<usize> {
    let applier = PatchApplier::new(workspace_path);
    let stats = applier.apply_findings(findings, args.dry_run)?;

    if args.dry_run {
        if stats.applied > 0 {
            eprintln!();
            eprintln!(
                "{} Would apply {} patch{} to {} file{}",
                "→".cyan().bold(),
                stats.applied.to_string().bright_green(),
                if stats.applied == 1 { "" } else { "es" },
                stats.modified_files.len().to_string().bright_green(),
                if stats.modified_files.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
        }
    } else if stats.applied > 0 {
        eprintln!();
        eprintln!(
            "{} Applied {} patch{} to {} file{}",
            "✓".green().bold(),
            stats.applied.to_string().bright_green(),
            if stats.applied == 1 { "" } else { "es" },
            stats.modified_files.len().to_string().bright_green(),
            if stats.modified_files.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for file in &stats.modified_files {
            eprintln!("  {} {}", "→".dimmed(), file);
        }
    }

    if !stats.errors.is_empty() {
        eprintln!();
        eprintln!("{} Some patches failed:", "⚠".yellow().bold());
        for error in &stats.errors {
            eprintln!("  {} {}", "→".red(), error);
        }
    }

    Ok(stats.applied)
}

/// Display context for IR analysis output.
struct ReviewOutputContext {
    workspace_label: String,
    languages: Vec<String>,
    frameworks: Vec<String>,
    dimensions: Vec<String>,
    file_count: usize,
    elapsed_ms: u64,
    parse_ms: u64,
    engine_ms: u64,
    cache_hit_rate: Option<f64>,
    trace_id: String,
    profile: Option<String>,
    slo_stats: Option<SloDiscoveryStats>,
    slo_definitions: Option<Vec<LlmSloDefinition>>,
}

/// Severity breakdown for the summary line.
struct SeveritySummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

fn compute_severity_summary(findings: &[IrFinding]) -> SeveritySummary {
    let mut summary = SeveritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for finding in findings {
        match finding.severity.to_lowercase().as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" => summary.low += 1,
            _ => {}
        }
    }

    summary
}

fn format_severity_breakdown(summary: &SeveritySummary) -> String {
    let mut parts: Vec<String> = Vec::new();

    if summary.critical > 0 {
        parts.push(format!(
            "{} critical",
            summary.critical.to_string().bright_red()
        ));
    }
    if summary.high > 0 {
        parts.push(format!("{} high", summary.high.to_string().bright_red()));
    }
    if summary.medium > 0 {
        parts.push(format!(
            "{} medium",
            summary.medium.to_string().bright_yellow()
        ));
    }
    if summary.low > 0 {
        parts.push(format!("{} low", summary.low.to_string().bright_blue()));
    }

    if parts.is_empty() {
        "—".into()
    } else {
        parts.join(&format!(" {} ", "·".dimmed()))
    }
}

/// Max width for terminal output (80 chars standard)
const MAX_WIDTH: usize = 80;

fn visible_len(s: &str) -> usize {
    // Handle ANSI escape sequences like "\x1b[...m" emitted by `colored`.
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut len = 0;

    while i < bytes.len() {
        if bytes[i] == 0x1b {
            // Skip ESC[...m
            if i + 1 < bytes.len() && bytes[i + 1] == b'[' {
                i += 2;
                while i < bytes.len() && bytes[i] != b'm' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                continue;
            }
        }

        // We only use this for wrapping terminal output; treating this as
        // byte length is ok for our ASCII-heavy CLI output.
        len += 1;
        i += 1;
    }

    len
}

/// Wrap text to fit within max_width, continuing on the next line with the given indent.
/// Returns a Vec of lines to print.
fn wrap_text(s: &str, first_line_max: usize, continuation_indent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let words: Vec<&str> = s.split_whitespace().collect();

    if words.is_empty() {
        return vec![String::new()];
    }

    let cont_max = MAX_WIDTH.saturating_sub(continuation_indent.len());

    let mut current_line = String::new();
    let mut current_max = first_line_max;

    for word in words {
        let word_len = visible_len(word);
        let current_len = visible_len(&current_line);

        // Check if we need to start a new line
        let would_fit = if current_len == 0 {
            word_len <= current_max
        } else {
            current_len + 1 + word_len <= current_max
        };

        if !would_fit && current_len > 0 {
            // Push the current line
            lines.push(current_line);
            // Start a new continuation line
            current_line = String::new();
            current_max = cont_max;
        }

        // Add the word to the current line
        if current_line.is_empty() {
            // If word is longer than max width, hard-break it.
            // Note: we don't attempt to hard-break colored strings; those should
            // be naturally short (paths, labels).
            if word_len > current_max {
                let mut remaining = word;
                while visible_len(remaining) > current_max {
                    let (chunk, rest) = remaining.split_at(current_max);
                    lines.push(chunk.to_string());
                    remaining = rest;
                    current_max = cont_max;
                }
                current_line = remaining.to_string();
            } else {
                current_line = word.to_string();
            }
        } else {
            current_line.push(' ');
            current_line.push_str(word);
        }
    }

    // Don't forget the last line
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

fn render_session_overview(context: &ReviewOutputContext) {
    // Line 1: Header with workspace name and total time
    println!(
        "{} Analyzing {}... {}",
        "→".cyan().bold(),
        context.workspace_label.bright_white(),
        format!("{}ms", context.elapsed_ms).dimmed()
    );

    // Line 2: Languages
    let langs = format_list(&context.languages, ", ");
    println!("  {}: {}", "Languages".dimmed(), langs.cyan());

    // Line 3: Frameworks
    let frameworks = format_list(&context.frameworks, ", ");
    println!("  {}: {}", "Frameworks".dimmed(), frameworks.cyan());

    // Line 4: Dimensions
    let dims = format_list(&context.dimensions, " · ");
    println!("  {}: {}", "Dimensions".dimmed(), dims.cyan());

    // Line 5: Profile (if overridden)
    if let Some(profile) = &context.profile {
        println!("  {}: {}", "Profile".dimmed(), profile.cyan());
    }

    // Line 6: Files reviewed with timing
    let file_word = if context.file_count == 1 {
        "file"
    } else {
        "files"
    };
    println!(
        "  {}: {} {} · parse {}ms · engine {}ms",
        "Reviewed".dimmed(),
        context.file_count.to_string().bright_green(),
        file_word,
        context.parse_ms,
        context.engine_ms
    );

    // Line 7: Cache and trace info
    let cache_str = match context.cache_hit_rate {
        Some(rate) => format!("{:.0}%", rate),
        None => "—".to_string(),
    };
    println!(
        "  {}: {}  {}: {}",
        "Cache".dimmed(),
        cache_str.dimmed(),
        "Trace".dimmed(),
        context.trace_id.dimmed()
    );
}

fn format_list(values: &[String], separator: &str) -> String {
    if values.is_empty() {
        "—".into()
    } else {
        values.join(separator)
    }
}

/// Render a compact one-line footer with metadata
/// Format: <long line>\n965ms - python / fastapi - 1 file
fn render_session_footer(context: &ReviewOutputContext) {
    // Long separator line
    println!("{}", "─".repeat(MAX_WIDTH).dimmed());

    // Compact metadata line: "965ms - python / fastapi - 1 file"
    let langs = format_list(&context.languages, ", ");
    let frameworks = format_list(&context.frameworks, ", ");

    let lang_framework = if frameworks == "—" {
        langs
    } else {
        format!("{} / {}", langs, frameworks)
    };

    let file_word = if context.file_count == 1 {
        "file"
    } else {
        "files"
    };

    println!(
        "{} - {} - {} {}",
        format!("{}ms", context.elapsed_ms).dimmed(),
        lang_framework.dimmed(),
        context.file_count,
        file_word.dimmed()
    );
}

fn display_ir_findings(
    args: &ReviewArgs,
    findings: &[IrFinding],
    applied_patches: usize,
    context: &ReviewOutputContext,
) {
    let total_findings = findings.len();

    if args.output_format == "llm" {
        let output = generate_llm_output(args, findings, context);
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    if args.output_format == "json" {
        let output = serde_json::json!({
            "findings_count": total_findings,
            "findings": findings,
            "patches_applied": applied_patches,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    if args.output_format == "sarif" {
        let sarif = generate_ir_sarif_output(findings, &context.workspace_label);
        println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
        return;
    }

    // Text output
    println!();

    render_session_overview(context);

    if total_findings == 0 {
        println!(
            "{} No issues found! Your code looks good.",
            "✓".bright_green().bold()
        );
        return;
    }

    // Blank line before the summary (matches landing page)
    println!();

    let hotspot_mode = args.output_mode != "full" && !args.raw_findings;

    if hotspot_mode {
        // Friendly narrative summary first
        let friendly_insights = generate_friendly_summary(findings);
        if !friendly_insights.is_empty() {
            println!("{} Quick take:", "💡".bold());
            for insight in &friendly_insights {
                println!("   {} {}", "·".dimmed(), insight);
            }
            println!();
        }

        println!(
            "{} Indexed {} signals",
            "⚠".yellow().bold(),
            total_findings.to_string().bright_yellow()
        );

        let summary = compute_severity_summary(findings);
        println!(
            "  {} {}",
            "Severity".dimmed(),
            format_severity_breakdown(&summary).dimmed()
        );
    } else {
        println!(
            "{} Found {} issue{}",
            "⚠".yellow().bold(),
            total_findings.to_string().bright_yellow(),
            if total_findings == 1 { "" } else { "s" }
        );

        // Severity breakdown line (like landing page: "4 high · 10 medium · 5 low")
        let summary = compute_severity_summary(findings);
        println!("{}", format_severity_breakdown(&summary));
    }

    if applied_patches > 0 {
        let verb = if args.dry_run {
            "Would apply"
        } else {
            "Applied"
        };
        println!(
            "  {} {} {} patch{}",
            if args.dry_run {
                "→".cyan().bold()
            } else {
                "✓".green().bold()
            },
            verb,
            applied_patches.to_string().bright_green(),
            if applied_patches == 1 { "" } else { "es" }
        );
    }

    println!();

    if args.output_mode == "full" {
        for finding in findings {
            display_ir_finding(finding);
        }
    } else if args.raw_findings {
        // Raw grouped display (old behavior)
        display_ir_findings_grouped(findings);
    } else {
        // Default: hotspot-first summary (scales to large repos)
        display_ir_hotspots_summary(findings);
    }
}

/// Display a single IR finding (full mode).
fn display_ir_finding(finding: &IrFinding) {
    let severity_color = match finding.severity.as_str() {
        "critical" | "Critical" => "red",
        "high" | "High" => "red",
        "medium" | "Medium" => "yellow",
        "low" | "Low" => "blue",
        _ => "white",
    };

    let severity_icon = match finding.severity.to_lowercase().as_str() {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🔵",
        _ => "⚪",
    };

    println!(
        "{} {} [{}]",
        severity_icon,
        finding.rule_id.bold(),
        finding.severity.color(severity_color)
    );

    println!("   {}", finding.message.dimmed());
    println!(
        "   File: {}:{}:{}",
        finding.file_path.cyan(),
        finding.line,
        finding.column
    );

    if let Some(patch) = &finding.patch {
        println!();
        println!("   {}", "Suggested fix:".green().bold());
        for line in patch.lines() {
            if line.starts_with('+') && !line.starts_with("+++") {
                println!("   {}", line.green());
            } else if line.starts_with('-') && !line.starts_with("---") {
                println!("   {}", line.red());
            } else {
                println!("   {}", line.dimmed());
            }
        }
    }
    println!();
}

/// Display IR findings grouped by severity and rule_id (basic mode).
/// Format matches the landing page TerminalDemo.
fn display_ir_findings_grouped(findings: &[IrFinding]) {
    use std::collections::BTreeMap;

    let severity_order = |s: &str| -> u8 {
        match s.to_lowercase().as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    };

    let mut grouped: BTreeMap<u8, BTreeMap<String, Vec<&IrFinding>>> = BTreeMap::new();

    for finding in findings {
        let sev_key = severity_order(&finding.severity);
        grouped
            .entry(sev_key)
            .or_default()
            .entry(finding.rule_id.clone())
            .or_default()
            .push(finding);
    }

    let mut first_severity = true;
    for (sev_key, rules_by_id) in &grouped {
        if !first_severity {
            println!();
        }
        first_severity = false;

        let severity_name = match sev_key {
            0 => "Critical",
            1 => "High",
            2 => "Medium",
            3 => "Low",
            _ => "Other",
        };

        let severity_icon = match sev_key {
            0 => "🔴",
            1 => "🟠",
            2 => "🟡",
            3 => "🔵",
            _ => "⚪",
        };

        let severity_color = match sev_key {
            0 | 1 => "red",
            2 => "yellow",
            3 => "blue",
            _ => "white",
        };

        let severity_count: usize = rules_by_id.values().map(|v| v.len()).sum();
        println!(
            "{} {} ({} issue{})",
            severity_icon,
            severity_name.color(severity_color).bold(),
            severity_count,
            if severity_count == 1 { "" } else { "s" }
        );

        // Display each rule as: [rule_id] title (matches landing page)
        // Format: "   [rule_id] title" - wrap to fit 80 chars
        for (rule_id, rule_findings) in rules_by_id {
            let sample = rule_findings[0];
            let title = if !sample.title.is_empty() {
                sample.title.clone()
            } else if !sample.message.is_empty() {
                sample.message.clone()
            } else {
                sample.rule_id.clone()
            };

            // Calculate available space: 80 - "   [" - rule_id - "] " = 80 - 5 - rule_id.len()
            let prefix_len = 5 + rule_id.len(); // "   [" + rule_id + "] "
            let first_line_max = MAX_WIDTH.saturating_sub(prefix_len);
            let continuation_indent = "      "; // 6 spaces for continuation lines

            let wrapped_lines = wrap_text(&title, first_line_max, continuation_indent);

            // Print first line with the rule_id prefix
            if let Some(first_line) = wrapped_lines.first() {
                println!("   [{}] {}", rule_id.cyan(), first_line.dimmed());
            }

            // Print continuation lines with indent
            for line in wrapped_lines.iter().skip(1) {
                println!("{}{}", continuation_indent, line.dimmed());
            }
        }
    }
}

fn shorten_example(title: &str) -> String {
    let mut t = title.trim().to_string();

    // Keep it compact.
    if let Some(idx) = t.find(" at line ") {
        t.truncate(idx);
    }

    if t.len() > 70 {
        t.truncate(67);
        t.push_str("...");
    }

    t
}

fn display_session_insights(
    args: &ReviewArgs,
    insights: &crate::api::SessionInsightsResponse,
    _context: &ReviewOutputContext,
) {
    // Filter test scopes unless explicitly included.
    let mut items: Vec<_> = insights
        .insights
        .iter()
        .filter(|i| args.include_tests || !is_test_path(&i.scope_key))
        .collect();

    if items.is_empty() {
        println!(
            "{} No issues found! Your code looks good.",
            "✓".bright_green().bold()
        );
        return;
    }

    // Keep this bounded and deterministic.
    items.truncate(8);

    use std::collections::HashMap;

    // Aggregate buckets across top insights.
    let mut bucket_counts: HashMap<String, i64> = HashMap::new();
    for i in &items {
        let bucket = i.evidence.group.bucket.clone();
        *bucket_counts.entry(bucket).or_insert(0) += i.evidence.group.count;
    }

    let mut buckets: Vec<(String, i64)> = bucket_counts.into_iter().collect();
    buckets.sort_by(|a, b| b.1.cmp(&a.1));
    buckets.truncate(2);

    let theme_phrase = |b: &str| match b {
        "resilience" => format!("{} hardening", "resilience".bright_yellow().bold()),
        "observability" => {
            format!(
                "{} (logging and tracing)",
                "observability".bright_yellow().bold()
            )
        }
        "security" => format!("{} hygiene", "security".bright_yellow().bold()),
        "performance" => format!("{} hot paths", "performance".bright_yellow().bold()),
        "correctness" => format!("{} edge cases", "correctness".bright_yellow().bold()),
        _ => format!("{} cleanup", "other".bright_yellow().bold()),
    };

    let mut paragraph = String::new();
    paragraph.push_str("Looks good overall, with a couple spots that deserve a closer look.");

    if buckets.len() == 2 {
        paragraph.push_str(&format!(
            " Two themes keep showing up: {} and {}.",
            theme_phrase(&buckets[0].0),
            theme_phrase(&buckets[1].0)
        ));
    } else if buckets.len() == 1 {
        paragraph.push_str(&format!(
            " One theme keeps showing up: {}.",
            theme_phrase(&buckets[0].0)
        ));
    }

    // Starting points: top 2 scopes with one example each.
    let mut starts: Vec<(String, Option<String>)> = Vec::new();
    for i in items.iter().take(2) {
        let example = i
            .evidence
            .facts
            .iter()
            .find_map(|f| f.title.as_deref().map(shorten_example));
        starts.push((i.scope_key.clone(), example));
    }

    if let Some((h1, ex1)) = starts.first() {
        paragraph.push_str(&format!(
            " Starting point: {}",
            h1.as_str().bright_purple().bold()
        ));
        if let Some(ex) = ex1 {
            paragraph.push_str(&format!(" ({})", ex));
        }

        if let Some((h2, ex2)) = starts.get(1) {
            paragraph.push_str(&format!("; then {}", h2.as_str().bright_purple().bold()));
            if let Some(ex) = ex2 {
                paragraph.push_str(&format!(" ({})", ex));
            }
        }
        paragraph.push('.');
    }

    if buckets.iter().any(|(b, _)| b == "observability") {
        paragraph.push_str(
            " If an incident hits, correlation IDs and structured logs make the follow-up a lot calmer.",
        );
    }

    let wrapped = wrap_text(&paragraph, MAX_WIDTH, "");
    for line in wrapped {
        println!("{}", line);
    }

    // Add friendly insights based on findings
    let insights = generate_friendly_insights_from_hotspots(items);
    if !insights.is_empty() {
        println!();
        println!("{}", "At a glance".dimmed());
        for insight in insights {
            println!("  {} {}", "·".dimmed(), insight);
        }
    }
}

/// Generate friendly insights from session insights
fn generate_friendly_insights_from_hotspots(
    items: Vec<&crate::api::SessionInsight>,
) -> Vec<String> {
    use std::collections::HashMap;

    // Count patterns across all evidence facts
    let mut patterns: HashMap<&str, usize> = HashMap::new();

    for item in items {
        for fact in &item.evidence.facts {
            let rule = fact.rule_id.as_deref().unwrap_or("").to_lowercase();

            if rule.contains("timeout") {
                *patterns.entry("timeout").or_default() += 1;
            } else if rule.contains("retry") {
                *patterns.entry("retry").or_default() += 1;
            } else if rule.contains("circuit") {
                *patterns.entry("circuit_breaker").or_default() += 1;
            } else if rule.contains("rate_limit") {
                *patterns.entry("rate_limit").or_default() += 1;
            } else if rule.contains("health") {
                *patterns.entry("health_check").or_default() += 1;
            } else if rule.contains("cors") {
                *patterns.entry("cors").or_default() += 1;
            } else if rule.contains("exception") || rule.contains("error_handler") {
                *patterns.entry("error_handling").or_default() += 1;
            } else if rule.contains("validation") || rule.contains("input") {
                *patterns.entry("validation").or_default() += 1;
            } else if rule.contains("secret") || rule.contains("injection") {
                *patterns.entry("security").or_default() += 1;
            }
        }
    }

    let mut insights = Vec::new();

    // Generate conversational insights
    if let Some(&count) = patterns.get("timeout") {
        if count > 1 {
            insights.push(format!(
                "{} calls without timeouts — could hang if a service is slow",
                count
            ));
        } else {
            insights.push("One call missing a timeout".to_string());
        }
    }

    if let Some(&count) = patterns.get("retry") {
        if count > 1 {
            insights.push(format!(
                "{} spots where retry logic would help with flaky networks",
                count
            ));
        } else {
            insights.push("One place could use retry logic".to_string());
        }
    }

    if patterns.contains_key("circuit_breaker") {
        insights
            .push("Circuit breakers would help fail fast when dependencies are down".to_string());
    }

    if patterns.contains_key("rate_limit") {
        insights.push("Rate limiting would protect against abuse".to_string());
    }

    if patterns.contains_key("health_check") {
        insights.push(
            "Health endpoints help load balancers and k8s know when you're ready".to_string(),
        );
    }

    if patterns.contains_key("cors") {
        insights.push("CORS config needed if browsers will call this API".to_string());
    }

    if let Some(&count) = patterns.get("error_handling") {
        if count > 1 {
            insights.push("Error handling could be more specific in a few places".to_string());
        }
    }

    if patterns.contains_key("security") {
        insights.push("Security concern flagged — worth a closer look".to_string());
    }

    // Keep it brief - max 4 insights
    insights.truncate(4);
    insights
}

/// Generate friendly insights from hotspot summaries (for basic output mode)
fn generate_friendly_insights_from_hotspot_summaries(
    hotspots: &[&crate::api::SessionHotspotSummary],
) -> Vec<String> {
    use std::collections::HashMap;

    // Count patterns across all example findings
    let mut patterns: HashMap<&str, usize> = HashMap::new();

    for hs in hotspots {
        for behavior in &hs.behaviors {
            for ex in &behavior.examples {
                let rule = ex.rule_id.to_lowercase();

                if rule.contains("timeout") {
                    *patterns.entry("timeout").or_default() += 1;
                } else if rule.contains("retry") {
                    *patterns.entry("retry").or_default() += 1;
                } else if rule.contains("circuit") {
                    *patterns.entry("circuit_breaker").or_default() += 1;
                } else if rule.contains("rate_limit") || rule.contains("rate_limiting") {
                    *patterns.entry("rate_limit").or_default() += 1;
                } else if rule.contains("health") {
                    *patterns.entry("health_check").or_default() += 1;
                } else if rule.contains("cors") {
                    *patterns.entry("cors").or_default() += 1;
                } else if rule.contains("exception") || rule.contains("error_handler") {
                    *patterns.entry("error_handling").or_default() += 1;
                } else if rule.contains("validation") || rule.contains("input_validation") {
                    *patterns.entry("validation").or_default() += 1;
                } else if rule.contains("secret") || rule.contains("injection") {
                    *patterns.entry("security").or_default() += 1;
                }
            }
        }
    }

    let mut insights = Vec::new();

    // Generate conversational insights
    if let Some(&count) = patterns.get("timeout") {
        if count > 1 {
            insights.push(format!(
                "{} calls without timeouts — could hang if a service is slow",
                count
            ));
        } else {
            insights.push("One call missing a timeout".to_string());
        }
    }

    if let Some(&count) = patterns.get("retry") {
        if count > 1 {
            insights.push(format!(
                "{} spots where retry logic would help with flaky networks",
                count
            ));
        } else {
            insights.push("One place could use retry logic".to_string());
        }
    }

    if patterns.contains_key("circuit_breaker") {
        insights
            .push("Circuit breakers would help fail fast when dependencies are down".to_string());
    }

    if patterns.contains_key("rate_limit") {
        insights.push("Rate limiting would protect against abuse".to_string());
    }

    if patterns.contains_key("health_check") {
        insights.push(
            "Health endpoints help load balancers and k8s know when you're ready".to_string(),
        );
    }

    if patterns.contains_key("cors") {
        insights.push("CORS config needed if browsers will call this API".to_string());
    }

    if let Some(&count) = patterns.get("error_handling") {
        if count > 1 {
            insights.push("Error handling could be more specific in a few places".to_string());
        }
    }

    if patterns.contains_key("security") {
        insights.push("Security concern flagged — worth a closer look".to_string());
    }

    // Keep it brief - max 4 insights
    insights.truncate(4);
    insights
}

fn display_session_hotspots(
    args: &ReviewArgs,
    hotspots: &crate::api::SessionHotspotsResponse,
    _context: &ReviewOutputContext,
) {
    // JSON/SARIF paths should not reach here
    if args.output_format == "json" {
        let output = serde_json::json!({
            "session_id": hotspots.session_id,
            "depth": hotspots.depth,
            "hotspots": hotspots.hotspots,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    let has_any = hotspots.hotspots.iter().any(|h| h.total_count > 0);
    if !has_any {
        println!(
            "{} No issues found! Your code looks good.",
            "✓".bright_green().bold()
        );
        return;
    }

    // Calm default: render a short, human Summary.
    if args.output_mode == "basic" {
        // Filter test hotspots unless explicitly included.
        let mut hs: Vec<_> = hotspots
            .hotspots
            .iter()
            .filter(|h| args.include_tests || !is_test_path(&h.hotspot))
            .collect();

        // The API already sorts hotspots by importance, but keep it deterministic.
        hs.truncate(8);

        // Aggregate bucket counts across top hotspots.
        use std::collections::HashMap;
        let mut bucket_counts: HashMap<String, i64> = HashMap::new();

        for h in &hs {
            for b in &h.behaviors {
                *bucket_counts.entry(b.bucket.clone()).or_insert(0) += b.count;
            }
        }

        let mut buckets: Vec<(String, i64)> = bucket_counts.into_iter().collect();
        buckets.sort_by(|a, b| b.1.cmp(&a.1));
        buckets.truncate(2);

        let theme_phrase = |b: &str| match b {
            "resilience" => format!("{} hardening", "resilience".bright_yellow().bold()),
            "observability" => {
                format!(
                    "{} (logging and tracing)",
                    "observability".bright_yellow().bold()
                )
            }
            "security" => format!("{} hygiene", "security".bright_yellow().bold()),
            "performance" => format!("{} hot paths", "performance".bright_yellow().bold()),
            "correctness" => format!("{} edge cases", "correctness".bright_yellow().bold()),
            _ => format!("{} cleanup", "other".bright_yellow().bold()),
        };

        let mut paragraph = String::new();

        paragraph.push_str("Looks good overall, with a couple spots that deserve a closer look.");

        if buckets.len() == 2 {
            paragraph.push_str(&format!(
                " Two themes keep showing up: {} and {}.",
                theme_phrase(&buckets[0].0),
                theme_phrase(&buckets[1].0)
            ));
        } else if buckets.len() == 1 {
            paragraph.push_str(&format!(
                " One theme keeps showing up: {}.",
                theme_phrase(&buckets[0].0)
            ));
        }

        // Starting points: top 2 hotspots with one example each.
        let mut starts: Vec<(String, Option<String>)> = Vec::new();
        for h in hs.iter().take(2) {
            let example = h
                .behaviors
                .iter()
                .flat_map(|b| b.examples.iter())
                .find_map(|ex| {
                    if !ex.title.is_empty() {
                        Some(shorten_example(&ex.title))
                    } else {
                        None
                    }
                });

            starts.push((h.hotspot.clone(), example));
        }

        if let Some((h1, ex1)) = starts.first() {
            paragraph.push_str(&format!(
                " Starting point: {}",
                h1.as_str().bright_purple().bold()
            ));
            if let Some(ex) = ex1 {
                paragraph.push_str(&format!(" ({})", ex));
            }

            if let Some((h2, ex2)) = starts.get(1) {
                paragraph.push_str(&format!("; then {}", h2.as_str().bright_purple().bold()));
                if let Some(ex) = ex2 {
                    paragraph.push_str(&format!(" ({})", ex));
                }
            }
            paragraph.push('.');
        }

        if buckets.iter().any(|(b, _)| b == "observability") {
            paragraph.push_str(
                " If an incident hits, correlation IDs and structured logs make the follow-up a lot calmer.",
            );
        }

        // Wrap to 80 columns.
        let wrapped = wrap_text(&paragraph, MAX_WIDTH, "");
        for line in wrapped {
            println!("{}", line);
        }

        // Add friendly "At a glance" insights from hotspot patterns
        let friendly_insights = generate_friendly_insights_from_hotspot_summaries(&hs);
        if !friendly_insights.is_empty() {
            println!();
            println!("{}", "At a glance".dimmed());
            for insight in friendly_insights {
                println!("  {} {}", "·".dimmed(), insight);
            }
        }

        return;
    }

    println!();
    println!("{}", "Hotspots".bold());

    for (i, hs) in hotspots.hotspots.iter().enumerate() {
        if i > 0 {
            println!();
        }

        println!(
            "  {} {} ({} signal{})",
            "→".cyan().bold(),
            hs.hotspot.bright_blue(),
            hs.total_count.to_string().bright_yellow(),
            if hs.total_count == 1 { "" } else { "s" }
        );

        for behavior in &hs.behaviors {
            println!(
                "    {}: {} signal{}",
                behavior.bucket.to_string().bold(),
                behavior.count.to_string().bright_yellow(),
                if behavior.count == 1 { "" } else { "s" }
            );

            for ex in &behavior.examples {
                let title = if !ex.title.is_empty() {
                    ex.title.clone()
                } else if !ex.description.is_empty() {
                    ex.description.clone()
                } else {
                    ex.rule_id.clone()
                };

                let prefix = format!("      [{}] ", ex.rule_id);
                let first_line_max = MAX_WIDTH.saturating_sub(prefix.len());
                let wrapped_lines = wrap_text(&title, first_line_max, "        ");

                if let Some(first_line) = wrapped_lines.first() {
                    println!("      [{}] {}", ex.rule_id.cyan(), first_line.dimmed());
                }
                for line in wrapped_lines.iter().skip(1) {
                    println!("        {}", line.dimmed());
                }

                let file_path = ex
                    .file_path
                    .clone()
                    .or_else(|| ex.location.as_ref().map(|l| l.file.clone()))
                    .unwrap_or_else(|| "".to_string());
                let line = ex
                    .line
                    .or_else(|| ex.location.as_ref().map(|l| l.start_line))
                    .unwrap_or(0);

                if !file_path.is_empty() {
                    println!(
                        "        {}:{}",
                        file_path.dimmed(),
                        line.to_string().dimmed()
                    );
                }
            }
        }
    }

    println!();
    println!(
        "  {} Run with {} for raw output (advanced)",
        "→".cyan().bold(),
        "--raw-findings".bright_blue()
    );
}

/// Generate a friendly narrative summary of findings (like a colleague's take)
fn generate_friendly_summary(findings: &[IrFinding]) -> Vec<String> {
    use std::collections::HashMap;

    // Count findings by category
    let mut categories: HashMap<&str, usize> = HashMap::new();

    for f in findings {
        let rule = f.rule_id.to_lowercase();

        if rule.contains("timeout") {
            *categories.entry("timeout").or_default() += 1;
        } else if rule.contains("retry") || rule.contains("circuit") {
            *categories.entry("retry").or_default() += 1;
        } else if rule.contains("logging") || rule.contains("trace") || rule.contains("correlation")
        {
            *categories.entry("observability").or_default() += 1;
        } else if rule.contains("secret") || rule.contains("injection") || rule.contains("security")
        {
            *categories.entry("security").or_default() += 1;
        } else if rule.contains("error") || rule.contains("exception") || rule.contains("handle") {
            *categories.entry("error_handling").or_default() += 1;
        } else if rule.contains("validation") || rule.contains("input") {
            *categories.entry("validation").or_default() += 1;
        } else if rule.contains("rate_limit")
            || rule.contains("cors")
            || rule.contains("middleware")
        {
            *categories.entry("api_protection").or_default() += 1;
        } else if rule.contains("health") {
            *categories.entry("health_check").or_default() += 1;
        }
    }

    let mut insights = Vec::new();

    // Generate friendly messages for top categories
    if let Some(&count) = categories.get("timeout") {
        if count >= 3 {
            insights.push(format!("{} external calls could use timeouts", count));
        } else if count > 0 {
            insights.push("A few external calls are missing timeouts".to_string());
        }
    }

    if let Some(&count) = categories.get("retry") {
        if count >= 3 {
            insights.push(format!("{} places could benefit from retry logic", count));
        } else if count > 0 {
            insights.push("Some calls might need retry logic for transient failures".to_string());
        }
    }

    if let Some(&count) = categories.get("error_handling") {
        if count >= 3 {
            insights.push("Error handling could be tightened up in a few spots".to_string());
        } else if count > 0 {
            insights.push("A couple of error handlers could be more specific".to_string());
        }
    }

    if let Some(&count) = categories.get("security") {
        if count > 0 {
            insights.push(format!(
                "{} security concern{} flagged",
                count,
                if count == 1 { "" } else { "s" }
            ));
        }
    }

    if let Some(&count) = categories.get("observability") {
        if count >= 3 {
            insights.push("Logging and tracing could be improved".to_string());
        } else if count > 0 {
            insights.push("A bit more logging would help with debugging".to_string());
        }
    }

    if let Some(&count) = categories.get("validation") {
        if count > 0 {
            insights.push("Some inputs could use stricter validation".to_string());
        }
    }

    if let Some(&count) = categories.get("api_protection") {
        if count > 0 {
            insights
                .push("API could use some protective middleware (rate limiting, CORS)".to_string());
        }
    }

    if let Some(&count) = categories.get("health_check") {
        if count > 0 {
            insights.push("Consider adding health check endpoints".to_string());
        }
    }

    // Limit to top 3 insights
    insights.truncate(3);
    insights
}

fn display_ir_hotspots_summary(findings: &[IrFinding]) {
    use std::collections::HashMap;

    const HOTSPOT_DEPTH: usize = 3;
    const HOTSPOT_LIMIT: usize = 10;
    const BEHAVIORS_PER_HOTSPOT: usize = 3;
    const EXAMPLES_PER_BEHAVIOR: usize = 3;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum BehaviorBucket {
        Resilience,
        Observability,
        Performance,
        Security,
        Correctness,
        Other,
    }

    impl BehaviorBucket {
        fn label(self) -> &'static str {
            match self {
                BehaviorBucket::Resilience => "Resilience",
                BehaviorBucket::Observability => "Observability",
                BehaviorBucket::Performance => "Performance",
                BehaviorBucket::Security => "Security",
                BehaviorBucket::Correctness => "Correctness",
                BehaviorBucket::Other => "Other",
            }
        }
    }

    fn severity_weight(sev: &str) -> i64 {
        match sev.to_lowercase().as_str() {
            "critical" => 10,
            "high" => 5,
            "medium" => 3,
            "low" => 1,
            _ => 0,
        }
    }

    fn bucket_for_rule(rule_id: &str) -> BehaviorBucket {
        let r = rule_id.to_lowercase();

        // Security
        if r.contains("sql_injection")
            || r.contains("hardcoded_secret")
            || r.contains("hardcoded_secrets")
            || r.contains("secret")
            || r.contains("xss")
            || r.contains("csrf")
            || r.contains("injection")
        {
            return BehaviorBucket::Security;
        }

        // Observability
        if r.contains("logging")
            || r.contains("correlation")
            || r.contains("trace")
            || r.contains("span")
        {
            return BehaviorBucket::Observability;
        }

        // Resilience
        if r.contains("timeout")
            || r.contains("retry")
            || r.contains("circuit")
            || r.contains("cancel")
            || r.contains("goroutine")
            || r.contains("recover")
            || r.contains("leak")
        {
            return BehaviorBucket::Resilience;
        }

        // Performance
        if r.contains("n_plus_one")
            || r.contains("unbounded")
            || r.contains("large_response")
            || r.contains("memory")
            || r.contains("regex_compile")
            || r.contains("pagination")
            || r.contains("alloc")
        {
            return BehaviorBucket::Performance;
        }

        // Correctness
        if r.contains("unchecked") || r.contains("bare_except") || r.contains("type_assert") {
            return BehaviorBucket::Correctness;
        }

        BehaviorBucket::Other
    }

    fn hotspot_key(file_path: &str) -> String {
        let parts: Vec<&str> = file_path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return "unknown".to_string();
        }
        let depth = HOTSPOT_DEPTH.min(parts.len());
        parts[..depth].join("/")
    }

    #[derive(Default)]
    struct BucketStats<'a> {
        count: usize,
        score: i64,
        examples: Vec<&'a IrFinding>,
    }

    #[derive(Default)]
    struct HotspotStats<'a> {
        total_count: usize,
        total_score: i64,
        buckets: HashMap<BehaviorBucket, BucketStats<'a>>,
    }

    fn insert_example<'a>(examples: &mut Vec<&'a IrFinding>, f: &'a IrFinding) {
        examples.push(f);
        examples.sort_by(|a, b| {
            severity_weight(&b.severity)
                .cmp(&severity_weight(&a.severity))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.file_path.cmp(&b.file_path))
                .then_with(|| a.line.cmp(&b.line))
        });
        examples.truncate(EXAMPLES_PER_BEHAVIOR);
    }

    let mut hotspots: HashMap<String, HotspotStats> = HashMap::new();

    for f in findings {
        let key = hotspot_key(&f.file_path);
        let bucket = bucket_for_rule(&f.rule_id);
        let w = severity_weight(&f.severity);

        let hs = hotspots.entry(key).or_default();
        hs.total_count += 1;
        hs.total_score += w;

        let bs = hs.buckets.entry(bucket).or_default();
        bs.count += 1;
        bs.score += w;
        insert_example(&mut bs.examples, f);
    }

    let mut sorted_hotspots: Vec<(String, HotspotStats)> = hotspots.into_iter().collect();
    sorted_hotspots.sort_by(|a, b| {
        b.1.total_score
            .cmp(&a.1.total_score)
            .then_with(|| a.0.cmp(&b.0))
    });
    sorted_hotspots.truncate(HOTSPOT_LIMIT);

    println!("{}", "Hotspots".bold());

    for (i, (key, hs)) in sorted_hotspots.iter().enumerate() {
        if i > 0 {
            println!();
        }

        println!(
            "  {} {} ({} finding{})",
            "→".cyan().bold(),
            key.bright_blue(),
            hs.total_count.to_string().bright_yellow(),
            if hs.total_count == 1 { "" } else { "s" }
        );

        let mut buckets: Vec<(BehaviorBucket, &BucketStats)> =
            hs.buckets.iter().map(|(k, v)| (*k, v)).collect();
        buckets.sort_by(|a, b| {
            b.1.score
                .cmp(&a.1.score)
                .then_with(|| a.0.label().cmp(b.0.label()))
        });
        buckets.truncate(BEHAVIORS_PER_HOTSPOT);

        for (bucket, stats) in buckets {
            println!(
                "    {}: {} finding{}",
                bucket.label().bold(),
                stats.count.to_string().bright_yellow(),
                if stats.count == 1 { "" } else { "s" }
            );

            for ex in &stats.examples {
                let title = if !ex.title.is_empty() {
                    ex.title.clone()
                } else if !ex.message.is_empty() {
                    ex.message.clone()
                } else {
                    ex.rule_id.clone()
                };

                let prefix = format!("      [{}] ", ex.rule_id);
                let first_line_max = MAX_WIDTH.saturating_sub(prefix.len());
                let wrapped_lines = wrap_text(&title, first_line_max, "        ");

                if let Some(first_line) = wrapped_lines.first() {
                    println!("      [{}] {}", ex.rule_id.cyan(), first_line.dimmed());
                }
                for line in wrapped_lines.iter().skip(1) {
                    println!("        {}", line.dimmed());
                }

                println!(
                    "        {}:{}",
                    ex.file_path.dimmed(),
                    ex.line.to_string().dimmed()
                );
            }
        }
    }

    println!();
    println!(
        "  {} Run with {} for raw output (advanced)",
        "→".cyan().bold(),
        "--raw-findings".bright_blue()
    );
}

/// SLO definition for LLM output
#[derive(Debug, Clone, serde::Serialize)]
struct LlmSloDefinition {
    id: String,
    name: String,
    provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_method: Option<String>,
    target_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_budget_remaining: Option<f64>,
    timeframe: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dashboard_url: Option<String>,
    monitored_route_count: usize,
    monitored_routes: Vec<String>,
}

/// Target location for LLM output
#[derive(Debug, Clone, serde::Serialize)]
struct LlmTarget {
    path: String,
    start_line: u32,
    start_col: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_col: Option<u32>,
}

/// Candidate fix for LLM output (advisory, not authoritative)
#[derive(Debug, Clone, serde::Serialize)]
struct LlmCandidateFix {
    fix_preview: String,
}

/// A single merged finding for LLM output
#[derive(Debug, Clone, serde::Serialize)]
struct LlmFinding {
    id: String,
    rule_id: String,
    severity: String,
    dimension: String,
    title: String,
    why: String,
    blast_radius: String,
    files_allowed_to_change: Vec<String>,
    targets: Vec<LlmTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_fix: Option<LlmCandidateFix>,
    merged_count: usize,
}

/// Top-level LLM review output
#[derive(Debug, Clone, serde::Serialize)]
struct LlmReviewOutput {
    schema_version: String,
    stop_conditions: Vec<String>,
    summary: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    slos: Option<Vec<LlmSloDefinition>>,
    apply_order: Vec<String>,
    findings: Vec<LlmFinding>,
}

/// Severity ranking for sorting (lower = more severe)
fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// Merge key: rule + file (treat as one task per file per rule)
fn llm_merge_key(f: &IrFinding) -> String {
    format!("{}::{}", f.rule_id, f.file_path)
}

/// Truncate string to max length with ellipsis
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}

/// Generate LLM-optimized JSON output for one-shot coding agent workflows.
fn generate_llm_output(
    args: &ReviewArgs,
    findings: &[IrFinding],
    context: &ReviewOutputContext,
) -> LlmReviewOutput {
    // Group findings by merge key (rule + file)
    let mut grouped: HashMap<String, Vec<&IrFinding>> = HashMap::new();
    for f in findings {
        grouped.entry(llm_merge_key(f)).or_default().push(f);
    }

    // Sort groups by severity (most severe first)
    let mut merged: Vec<(&String, &Vec<&IrFinding>)> = grouped.iter().collect();
    merged.sort_by(|a, b| {
        let a_sev = severity_rank(&a.1[0].severity);
        let b_sev = severity_rank(&b.1[0].severity);
        a_sev.cmp(&b_sev)
    });

    // Apply top-N limit (default 50, max 200)
    let top_n = args.top.unwrap_or(50).clamp(1, 200);
    merged.truncate(top_n);

    // Build output
    let stop_conditions = vec![
        "Do not refactor unrelated code.".to_string(),
        "Do not rename public APIs unless required by a fix.".to_string(),
        "Do not broaden scope beyond files_allowed_to_change.".to_string(),
        "Keep edits minimal and local.".to_string(),
    ];

    let summary = serde_json::json!({
        "workspace": context.workspace_label,
        "file_count": context.file_count,
        "elapsed_ms": context.elapsed_ms,
        "findings_total": findings.len(),
        "findings_returned": merged.len(),
        "top": top_n,
        "observability": {
            "attempted": context.slo_stats.as_ref().map(|s| s.attempted).unwrap_or(false),
            "slo_count": context.slo_stats.as_ref().map(|s| s.slo_count).unwrap_or(0),
            "monitored_routes": context.slo_stats.as_ref().map(|s| s.monitored_routes).unwrap_or(0),
            "total_routes": context.slo_stats.as_ref().map(|s| s.total_routes).unwrap_or(0),
            "credentials_expired": context.slo_stats.as_ref().map(|s| s.credentials_expired).unwrap_or(false),
            "no_credentials": context.slo_stats.as_ref().map(|s| s.no_credentials).unwrap_or(false)
        }
    });

    let mut apply_order = Vec::new();
    let mut out_findings = Vec::new();

    for (idx, (_key, fs)) in merged.into_iter().enumerate() {
        let id = format!("F-{:04}", idx + 1);
        apply_order.push(id.clone());

        let rep = fs[0]; // Representative finding

        // Collect all targets from merged findings
        let targets: Vec<LlmTarget> = fs
            .iter()
            .map(|f| LlmTarget {
                path: f.file_path.clone(),
                start_line: f.line,
                start_col: f.column,
                end_line: f.end_line,
                end_col: f.end_column,
            })
            .collect();

        // Build "why" from description or message
        let why = if !rep.description.is_empty() {
            truncate_str(&rep.description, 300)
        } else if !rep.message.is_empty() {
            truncate_str(&rep.message, 300)
        } else {
            "Issue detected by rule.".to_string()
        };

        // Include candidate fix if available (advisory only)
        let candidate_fix = rep.fix_preview.as_ref().map(|p| LlmCandidateFix {
            fix_preview: truncate_str(p, 500),
        });

        out_findings.push(LlmFinding {
            id,
            rule_id: rep.rule_id.clone(),
            severity: rep.severity.clone(),
            dimension: rep.dimension.clone(),
            title: if rep.title.is_empty() {
                rep.rule_id.clone()
            } else {
                rep.title.clone()
            },
            why,
            blast_radius: "local".to_string(),
            files_allowed_to_change: vec![rep.file_path.clone()],
            targets,
            candidate_fix,
            merged_count: fs.len(),
        });
    }

    LlmReviewOutput {
        schema_version: "unfault.llm_review.v1".to_string(),
        stop_conditions,
        summary,
        slos: context.slo_definitions.clone(),
        apply_order,
        findings: out_findings,
    }
}

/// Generate SARIF 2.1.0 output for GitHub Code Scanning and IDE integration.
fn generate_ir_sarif_output(findings: &[IrFinding], workspace_label: &str) -> serde_json::Value {
    let mut rules_map: HashMap<String, &IrFinding> = HashMap::new();
    for finding in findings {
        rules_map.entry(finding.rule_id.clone()).or_insert(finding);
    }

    let rules: Vec<serde_json::Value> = rules_map
        .iter()
        .map(|(rule_id, finding)| {
            let mut rule = serde_json::json!({
                "id": rule_id,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.description
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&finding.severity)
                },
                "properties": {
                    "tags": [finding.dimension.to_lowercase()],
                    "precision": "high"
                }
            });

            if let Some(obj) = rule.as_object_mut() {
                obj.insert(
                    "helpUri".to_string(),
                    serde_json::json!(format!(
                        "https://docs.unfault.dev/rules/{}",
                        rule_id.replace('.', "/")
                    )),
                );
            }

            rule
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            let mut result = serde_json::json!({
                "ruleId": finding.rule_id,
                "level": severity_to_sarif_level(&finding.severity),
                "message": {
                    "text": finding.message
                },
                "properties": {
                    "dimension": finding.dimension
                }
            });

            if !finding.file_path.is_empty() && finding.line > 0 {
                let mut region = serde_json::json!({
                    "startLine": finding.line
                });

                if let Some(end_line) = finding.end_line {
                    region["endLine"] = serde_json::json!(end_line);
                }

                if finding.column > 0 {
                    region["startColumn"] = serde_json::json!(finding.column);
                }

                if let Some(end_column) = finding.end_column {
                    region["endColumn"] = serde_json::json!(end_column);
                }

                if let Some(obj) = result.as_object_mut() {
                    obj.insert(
                        "locations".to_string(),
                        serde_json::json!([{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.file_path,
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": region
                            }
                        }]),
                    );
                }
            }

            if let Some(diff) = &finding.patch {
                if !finding.file_path.is_empty() && finding.line > 0 {
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert(
                            "fixes".to_string(),
                            serde_json::json!([{
                                "description": {
                                    "text": "Apply suggested fix"
                                },
                                "artifactChanges": [{
                                    "artifactLocation": {
                                        "uri": finding.file_path,
                                        "uriBaseId": "%SRCROOT%"
                                    },
                                    "replacements": [{
                                        "deletedRegion": {
                                            "startLine": finding.line,
                                            "endLine": finding.end_line.unwrap_or(finding.line)
                                        },
                                        "insertedContent": {
                                            "text": extract_fix_from_diff(diff)
                                        }
                                    }]
                                }]
                            }]),
                        );
                    }
                }
            }

            result
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "unfault",
                    "informationUri": "https://unfault.dev",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results,
            "originalUriBaseIds": {
                "%SRCROOT%": {
                    "uri": format!("file://{}/", workspace_label),
                    "description": {
                        "text": "The root directory of the analyzed workspace"
                    }
                }
            }
        }]
    })
}

/// Convert Unfault severity to SARIF level
fn severity_to_sarif_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "warning",
    }
}

/// Extract the replacement text from a unified diff
fn extract_fix_from_diff(diff: &str) -> String {
    diff.lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .map(|line| &line[1..]) // Remove the leading '+'
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::WorkspaceScanner;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_is_test_path_common_patterns() {
        assert!(is_test_path("tests/test_api.py"));
        assert!(is_test_path("src/__tests__/widget.test.tsx"));
        assert!(is_test_path("pkg/foo_test.go"));
        assert!(is_test_path("testdata/corpus.json"));
        assert!(is_test_path("fixtures/sample.yaml"));
        assert!(is_test_path("tests\\unit\\spec_auth.rs"));

        assert!(!is_test_path("src/main.py"));
        assert!(!is_test_path("src/testament.rs"));
        assert!(!is_test_path("src/contest/winner.rs"));
    }

    #[test]
    fn test_wrap_text_is_ansi_aware() {
        let path = "scripts/create-plan.py".bright_purple().bold().to_string();
        let s = format!(
            "Starting point: {} (something with enough words to wrap cleanly at eighty columns)",
            path
        );

        let lines = wrap_text(&s, MAX_WIDTH, "");
        assert!(lines.len() > 1);
        for line in lines {
            assert!(visible_len(&line) <= MAX_WIDTH);
        }
    }

    #[test]
    fn test_workspace_scanner_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.source_files.is_empty());
    }
    #[test]
    fn test_workspace_scanner_python_files() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("main.py");
        fs::write(&file_path, "print('hello')").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert_eq!(info.source_files.len(), 1);
    }
    #[test]
    fn test_workspace_scanner_fastapi_detection() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("app.py");
        fs::write(&file_path, "from fastapi import FastAPI\napp = FastAPI()").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.frameworks.iter().any(|f| f.name == "fastapi"));
    }
    #[test]
    fn test_display_ir_finding_does_not_panic() {
        let finding = IrFinding {
            rule_id: "test.rule".to_string(),
            title: "Test Finding".to_string(),
            description: "This is a test finding".to_string(),
            severity: "Medium".to_string(),
            dimension: "Stability".to_string(),
            file_path: "src/main.py".to_string(),
            line: 10,
            column: 5,
            end_line: Some(12),
            end_column: Some(40),
            message: "This is a test finding".to_string(),
            patch_json: None,
            fix_preview: None,
            patch: None,
            byte_start: None,
            byte_end: None,
        };

        display_ir_finding(&finding);
    }

    #[test]
    fn test_display_ir_findings_grouped_does_not_panic() {
        let findings = vec![
            IrFinding {
                rule_id: "http.timeout".to_string(),
                title: "Missing HTTP timeout".to_string(),
                description: "HTTP call without timeout".to_string(),
                severity: "High".to_string(),
                dimension: "Stability".to_string(),
                file_path: "src/main.py".to_string(),
                line: 10,
                column: 1,
                end_line: None,
                end_column: None,
                message: "HTTP call without timeout".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            },
            IrFinding {
                rule_id: "http.timeout".to_string(),
                title: "Missing HTTP timeout".to_string(),
                description: "Another HTTP call without timeout".to_string(),
                severity: "High".to_string(),
                dimension: "Stability".to_string(),
                file_path: "src/main.py".to_string(),
                line: 20,
                column: 1,
                end_line: None,
                end_column: None,
                message: "Another HTTP call without timeout".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            },
            IrFinding {
                rule_id: "cors.missing".to_string(),
                title: "Missing CORS".to_string(),
                description: "No CORS configured".to_string(),
                severity: "Medium".to_string(),
                dimension: "Correctness".to_string(),
                file_path: "src/main.py".to_string(),
                line: 30,
                column: 1,
                end_line: None,
                end_column: None,
                message: "No CORS configured".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            },
            IrFinding {
                rule_id: "critical.issue".to_string(),
                title: "Critical Issue".to_string(),
                description: "A critical issue".to_string(),
                severity: "Critical".to_string(),
                dimension: "Stability".to_string(),
                file_path: "src/main.py".to_string(),
                line: 40,
                column: 1,
                end_line: None,
                end_column: None,
                message: "A critical issue".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            },
        ];

        display_ir_findings_grouped(&findings);
    }

    #[test]
    fn test_sarif_output_generation() {
        let findings = vec![IrFinding {
            rule_id: "python.http.missing_timeout".to_string(),
            title: "Missing HTTP timeout".to_string(),
            description: "HTTP request without timeout".to_string(),
            severity: "High".to_string(),
            dimension: "Stability".to_string(),
            file_path: "src/main.py".to_string(),
            line: 10,
            column: 5,
            end_line: Some(12),
            end_column: Some(40),
            message: "HTTP request without timeout".to_string(),
            patch_json: None,
            fix_preview: None,
            patch: Some(
                "--- a/src/main.py\n+++ b/src/main.py\n@@ -10,1 +10,1 @@\n-requests.get(url)\n+requests.get(url, timeout=30)"
                    .to_string(),
            ),
            byte_start: None,
            byte_end: None,
        }];

        let sarif = generate_ir_sarif_output(&findings, "test-workspace");

        // Verify SARIF structure
        assert_eq!(sarif["version"], "2.1.0");
        assert!(
            sarif["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0")
        );

        // Verify tool info
        let tool = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(tool["name"], "unfault");

        // Verify rules
        let rules = tool["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "python.http.missing_timeout");

        // Verify results
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "python.http.missing_timeout");
        assert_eq!(results[0]["level"], "error"); // High severity -> error

        // Verify location
        let location = &results[0]["locations"][0]["physicalLocation"];
        assert_eq!(location["artifactLocation"]["uri"], "src/main.py");
        assert_eq!(location["region"]["startLine"], 10);
        assert_eq!(location["region"]["endLine"], 12);
    }

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level("Critical"), "error");
        assert_eq!(severity_to_sarif_level("High"), "error");
        assert_eq!(severity_to_sarif_level("Medium"), "warning");
        assert_eq!(severity_to_sarif_level("Low"), "note");
        assert_eq!(severity_to_sarif_level("Info"), "note");
        assert_eq!(severity_to_sarif_level("Unknown"), "warning");
    }

    #[test]
    fn test_extract_fix_from_diff() {
        let diff = "--- a/src/main.py\n+++ b/src/main.py\n@@ -10,1 +10,1 @@\n-old_line\n+new_line\n+another_new_line";
        let fix = extract_fix_from_diff(diff);
        assert_eq!(fix, "new_line\nanother_new_line");
    }

    #[test]
    fn test_display_ir_findings_grouped_empty() {
        let findings: Vec<IrFinding> = vec![];
        display_ir_findings_grouped(&findings);
    }

    #[test]
    fn test_generate_llm_output_schema_version() {
        let args = ReviewArgs {
            output_format: "llm".to_string(),
            output_mode: "full".to_string(),
            verbose: false,
            profile: None,
            dimensions: None,
            dry_run: false,
            raw_findings: false,
            include_tests: false,
            discover_observability: false,
            top: None,
            files: None,
            uncommitted: false,
        };
        let context = ReviewOutputContext {
            workspace_label: "test-workspace".to_string(),
            languages: vec!["python".to_string()],
            frameworks: vec!["fastapi".to_string()],
            dimensions: vec!["stability".to_string()],
            file_count: 10,
            elapsed_ms: 100,
            parse_ms: 50,
            engine_ms: 50,
            cache_hit_rate: Some(0.5),
            trace_id: "test-trace".to_string(),
            profile: Some("fastapi".to_string()),
            slo_stats: None,
            slo_definitions: None,
        };

        let findings = vec![IrFinding {
            rule_id: "missing.timeout".to_string(),
            title: "Missing timeout".to_string(),
            description: "HTTP request without timeout".to_string(),
            severity: "High".to_string(),
            dimension: "Stability".to_string(),
            file_path: "src/main.py".to_string(),
            line: 10,
            column: 5,
            end_line: Some(10),
            end_column: Some(30),
            message: "Add timeout".to_string(),
            patch_json: None,
            fix_preview: Some("requests.get(url, timeout=30)".to_string()),
            patch: None,
            byte_start: None,
            byte_end: None,
        }];

        let output = generate_llm_output(&args, &findings, &context);

        assert_eq!(output.schema_version, "unfault.llm_review.v1");
        assert_eq!(output.stop_conditions.len(), 4);
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.apply_order, vec!["F-0001"]);
        assert!(output.slos.is_none());
        assert!(
            !output.summary["observability"]["attempted"]
                .as_bool()
                .unwrap()
        );

        let finding = &output.findings[0];
        assert_eq!(finding.id, "F-0001");
        assert_eq!(finding.rule_id, "missing.timeout");
        assert_eq!(finding.severity, "High");
        assert_eq!(finding.blast_radius, "local");
        assert_eq!(finding.files_allowed_to_change, vec!["src/main.py"]);
        assert_eq!(finding.merged_count, 1);
        assert!(finding.candidate_fix.is_some());
    }

    #[test]
    fn test_generate_llm_output_merging() {
        let args = ReviewArgs {
            output_format: "llm".to_string(),
            output_mode: "full".to_string(),
            verbose: false,
            profile: None,
            dimensions: None,
            dry_run: false,
            raw_findings: false,
            include_tests: false,
            discover_observability: false,
            top: None,
            files: None,
            uncommitted: false,
        };
        let context = ReviewOutputContext {
            workspace_label: "test-workspace".to_string(),
            languages: vec![],
            frameworks: vec![],
            dimensions: vec![],
            file_count: 5,
            elapsed_ms: 50,
            parse_ms: 25,
            engine_ms: 25,
            cache_hit_rate: None,
            trace_id: "test".to_string(),
            profile: None,
            slo_stats: None,
            slo_definitions: None,
        };

        // Two findings with same rule+file should merge
        let findings = vec![
            IrFinding {
                rule_id: "missing.timeout".to_string(),
                title: "Missing timeout".to_string(),
                description: "Desc".to_string(),
                severity: "High".to_string(),
                dimension: "Stability".to_string(),
                file_path: "src/main.py".to_string(),
                line: 10,
                column: 1,
                end_line: None,
                end_column: None,
                message: "".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            },
            IrFinding {
                rule_id: "missing.timeout".to_string(),
                title: "Missing timeout".to_string(),
                description: "Desc".to_string(),
                severity: "High".to_string(),
                dimension: "Stability".to_string(),
                file_path: "src/main.py".to_string(),
                line: 20,
                column: 1,
                end_line: None,
                end_column: None,
                message: "".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            },
            // Different file, same rule - should NOT merge
            IrFinding {
                rule_id: "missing.timeout".to_string(),
                title: "Missing timeout".to_string(),
                description: "Desc".to_string(),
                severity: "High".to_string(),
                dimension: "Stability".to_string(),
                file_path: "src/other.py".to_string(),
                line: 5,
                column: 1,
                end_line: None,
                end_column: None,
                message: "".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            },
        ];

        let output = generate_llm_output(&args, &findings, &context);

        // Should have 2 findings (merged by rule+file)
        assert_eq!(output.findings.len(), 2);

        // First finding (same file) should have merged_count=2 with 2 targets
        let merged_finding = output
            .findings
            .iter()
            .find(|f| f.merged_count == 2)
            .expect("Should have a merged finding");
        assert_eq!(merged_finding.targets.len(), 2);

        // Check summary reflects original count
        let findings_total = output.summary["findings_total"].as_u64().unwrap();
        assert_eq!(findings_total, 3);

        let findings_returned = output.summary["findings_returned"].as_u64().unwrap();
        assert_eq!(findings_returned, 2);
    }

    #[test]
    fn test_generate_llm_output_top_limit() {
        let args = ReviewArgs {
            output_format: "llm".to_string(),
            output_mode: "full".to_string(),
            verbose: false,
            profile: None,
            dimensions: None,
            dry_run: false,
            raw_findings: false,
            include_tests: false,
            discover_observability: false,
            top: Some(2), // Limit to 2
            files: None,
            uncommitted: false,
        };
        let context = ReviewOutputContext {
            workspace_label: "test".to_string(),
            languages: vec![],
            frameworks: vec![],
            dimensions: vec![],
            file_count: 1,
            elapsed_ms: 10,
            parse_ms: 5,
            engine_ms: 5,
            cache_hit_rate: None,
            trace_id: "test".to_string(),
            profile: None,
            slo_stats: None,
            slo_definitions: None,
        };

        // Create 5 findings, each in different file (so they don't merge)
        let findings: Vec<IrFinding> = (1..=5)
            .map(|i| IrFinding {
                rule_id: format!("rule.{}", i),
                title: format!("Rule {}", i),
                description: "Desc".to_string(),
                severity: if i == 1 {
                    "Critical".to_string()
                } else if i == 2 {
                    "High".to_string()
                } else {
                    "Medium".to_string()
                },
                dimension: "Stability".to_string(),
                file_path: format!("file{}.py", i),
                line: 1,
                column: 1,
                end_line: None,
                end_column: None,
                message: "".to_string(),
                patch_json: None,
                fix_preview: None,
                patch: None,
                byte_start: None,
                byte_end: None,
            })
            .collect();

        let output = generate_llm_output(&args, &findings, &context);

        // Should be limited to 2 findings
        assert_eq!(output.findings.len(), 2);
        assert_eq!(output.apply_order.len(), 2);

        // Should be sorted by severity (Critical first, then High)
        assert_eq!(output.findings[0].severity, "Critical");
        assert_eq!(output.findings[1].severity, "High");

        // Summary should reflect the limit
        assert_eq!(output.summary["top"].as_u64().unwrap(), 2);
        assert_eq!(output.summary["findings_total"].as_u64().unwrap(), 5);
        assert_eq!(output.summary["findings_returned"].as_u64().unwrap(), 2);
    }

    #[test]
    fn test_severity_rank() {
        assert_eq!(severity_rank("Critical"), 0);
        assert_eq!(severity_rank("critical"), 0);
        assert_eq!(severity_rank("High"), 1);
        assert_eq!(severity_rank("Medium"), 2);
        assert_eq!(severity_rank("Low"), 3);
        assert_eq!(severity_rank("Info"), 4);
        assert_eq!(severity_rank("unknown"), 5);
    }

    #[test]
    fn test_llm_merge_key() {
        let finding = IrFinding {
            rule_id: "rule.test".to_string(),
            title: "".to_string(),
            description: "".to_string(),
            severity: "High".to_string(),
            dimension: "".to_string(),
            file_path: "src/main.py".to_string(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            message: "".to_string(),
            patch_json: None,
            fix_preview: None,
            patch: None,
            byte_start: None,
            byte_end: None,
        };
        assert_eq!(llm_merge_key(&finding), "rule.test::src/main.py");
    }

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("short", 10), "short");
        assert_eq!(truncate_str("this is a long string", 10), "this is a…");
        assert_eq!(truncate_str("exact", 5), "exact");
    }

    #[test]
    fn test_get_uncommitted_files_non_git_dir() {
        // Create a temp dir that's not a git repo
        let temp_dir = tempfile::tempdir().unwrap();
        let result = get_uncommitted_files(temp_dir.path());
        assert!(result.is_none());
    }

    #[test]
    fn test_get_uncommitted_files_clean_repo() {
        use std::process::Command;

        // Create a temp git repo
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();

        // Initialize git repo
        Command::new("git")
            .args(["init"])
            .current_dir(path)
            .output()
            .unwrap();

        // Configure git user for the repo
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(path)
            .output()
            .unwrap();

        // Create and commit a file
        std::fs::write(path.join("file.txt"), "content").unwrap();
        Command::new("git")
            .args(["add", "file.txt"])
            .current_dir(path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(path)
            .output()
            .unwrap();

        // Should return empty list for clean repo
        let result = get_uncommitted_files(path);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_get_uncommitted_files_with_changes() {
        use std::process::Command;

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();

        // Initialize git repo
        Command::new("git")
            .args(["init"])
            .current_dir(path)
            .output()
            .unwrap();

        // Configure git user
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(path)
            .output()
            .unwrap();

        // Create and commit initial file
        std::fs::write(path.join("committed.txt"), "content").unwrap();
        Command::new("git")
            .args(["add", "committed.txt"])
            .current_dir(path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(path)
            .output()
            .unwrap();

        // Create uncommitted changes:
        // 1. Modified file (unstaged)
        std::fs::write(path.join("committed.txt"), "modified").unwrap();
        // 2. Staged file
        std::fs::write(path.join("staged.txt"), "staged").unwrap();
        Command::new("git")
            .args(["add", "staged.txt"])
            .current_dir(path)
            .output()
            .unwrap();
        // 3. Untracked file
        std::fs::write(path.join("untracked.txt"), "new").unwrap();

        let result = get_uncommitted_files(path);
        assert!(result.is_some());
        let files = result.unwrap();

        // Should contain all three types
        assert!(files.contains(&"committed.txt".to_string())); // modified
        assert!(files.contains(&"staged.txt".to_string())); // staged
        assert!(files.contains(&"untracked.txt".to_string())); // untracked
    }
}

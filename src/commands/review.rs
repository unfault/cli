// unfault-ignore: rust.println_in_lib
//! # Review Command
//!
//! Implements the code review/analysis command for the Unfault CLI.
//!
//! ## Architecture
//!
//! By default, the review command uses **client-side parsing**:
//! 1. Parse source files locally using tree-sitter (via unfault-core)
//! 2. Build an Intermediate Representation (IR) containing semantics and code graph
//! 3. Send serialized IR to the API (no source code over the wire)
//! 4. Receive findings and optionally apply patches locally
//!
//! Use `--server-parse` flag to fall back to legacy server-side parsing.
//!
//! ## Usage
//!
//! ```bash
//! unfault review               # Client-side parsing (default)
//! unfault review --fix         # Auto-apply all fixes
//! unfault review --dry-run     # Show what fixes would be applied
//! unfault review --server-parse # Legacy: send source to server
//! unfault review --output full
//! unfault review --output json
//! unfault review --output sarif
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::api::graph::IrFinding;
use crate::api::{ApiClient, ApiError, SessionContextInput, SubscriptionWarning};
use crate::config::Config;
use crate::errors::{
    display_auth_error, display_config_error, display_network_error, display_service_error,
    display_validation_error,
};
use crate::exit_codes::*;
use crate::session::{
    build_ir_cached, compute_workspace_id, get_git_remote, FileCollector, PatchApplier, ScanProgress,
    SessionRunner, WorkspaceScanner,
};

/// Display a subscription warning banner (non-blocking nudge).
///
/// This is used to inform users about trial expiration without blocking their workflow.
fn display_subscription_warning(warning: &SubscriptionWarning) {
    let icon = match warning.warning_type.as_str() {
        "trial_ending" => "ℹ",
        "trial_expired" => "⚠",
        _ => "ℹ",
    };

    let color = match warning.warning_type.as_str() {
        "trial_ending" => "cyan",
        "trial_expired" => "yellow",
        _ => "white",
    };

    eprintln!();
    eprintln!(
        "{} {}",
        icon.color(color).bold(),
        warning.message.color(color)
    );
    eprintln!(
        "  Subscribe at: {}",
        warning.upgrade_url.underline().bright_blue()
    );
    eprintln!();
}

/// Display a message about limited results due to expired trial.
fn display_limited_results_notice(shown_count: usize, total_count: i32) {
    let hidden_count = total_count as usize - shown_count;
    if hidden_count > 0 {
        eprintln!();
        eprintln!(
            "  {} {} more issue{} available with subscription",
            "→".bright_blue(),
            hidden_count.to_string().bright_yellow(),
            if hidden_count == 1 { "" } else { "s" }
        );
    }
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
    /// Output format (text, json, or sarif)
    pub output_format: String,
    /// Output mode (concise or full)
    pub output_mode: String,
    /// Verbose mode (dump raw responses)
    pub verbose: bool,
    /// Override the detected profile
    pub profile: Option<String>,
    /// Dimensions to analyze (None = all from profile)
    pub dimensions: Option<Vec<String>>,
    /// Auto-apply all suggested fixes
    pub fix: bool,
    /// Show what fixes would be applied without actually applying them
    pub dry_run: bool,
    /// Use legacy server-side parsing (sends source code to server)
    pub server_parse: bool,
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
#[derive(Default)]
struct ScanDisplayState {
    languages: Vec<String>,
    frameworks: Vec<String>,
    file_count: usize,
    lines_printed: usize,
}

impl ScanDisplayState {
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
        eprintln!("  Dimensions: {}", dimensions.join(", ").cyan());
        lines += 1;

        // File count line (always show, even if 0)
        eprintln!(
            "  Found {} matching source files",
            self.file_count.to_string().bright_green()
        );
        lines += 1;

        self.lines_printed = lines;
        let _ = io::stderr().flush();
    }
}

pub async fn execute(args: ReviewArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
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

    // Start timing the session
    let session_start = Instant::now();

    // Get workspace label first (just the directory name)
    let workspace_label = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace")
        .to_string();

    // Print header immediately
    let mode_indicator = if args.server_parse {
        " (server-parse)"
    } else {
        ""
    };
    eprintln!(
        "{} Analyzing {}{}...",
        "→".cyan().bold(),
        workspace_label.bright_blue(),
        mode_indicator.dimmed()
    );

    // Determine dimensions to analyze (needed for display)
    let dimensions: Vec<String> = args.dimensions.clone().unwrap_or_else(|| {
        vec![
            "stability".to_string(),
            "correctness".to_string(),
            "performance".to_string(),
        ]
    });

    // Set up progressive display state
    let display_state = Arc::new(Mutex::new(ScanDisplayState::default()));
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
        state.file_count = workspace_info.source_files.len();
        state.languages = workspace_info.language_strings();
        state.frameworks = workspace_info.framework_strings();
        state.render(&dimensions, args.profile.as_deref());
    }

    if workspace_info.source_files.is_empty() {
        eprintln!(
            "{} No source files found in the current directory.",
            "⚠".yellow().bold()
        );
        return Ok(EXIT_SUCCESS);
    }

    // Branch: Server-side parsing (legacy) vs Client-side parsing (default)
    if args.server_parse {
        // Legacy mode: send source code to server
        execute_server_parse(
            &args,
            &config,
            &api_client,
            &trace_id,
            &current_dir,
            &workspace_label,
            &dimensions,
            &workspace_info,
            session_start,
        )
        .await
    } else {
        // New default: client-side parsing
        execute_client_parse(
            &args,
            &config,
            &api_client,
            &trace_id,
            &current_dir,
            &workspace_label,
            &dimensions,
            &workspace_info,
            session_start,
        )
        .await
    }
}

/// Execute review with client-side parsing (default mode).
///
/// 1. Parse source files locally using tree-sitter
/// 2. Build IR (semantics + graph)
/// 3. Serialize and send IR to API
/// 4. Receive findings and optionally apply patches
async fn execute_client_parse(
    args: &ReviewArgs,
    config: &Config,
    api_client: &ApiClient,
    trace_id: &str,
    current_dir: &std::path::Path,
    workspace_label: &str,
    _dimensions: &[String],
    workspace_info: &crate::session::WorkspaceInfo,
    session_start: Instant,
) -> Result<i32> {
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
    let build_result = match build_ir_cached(current_dir, None, args.verbose) {
        Ok(result) => result,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!(
                "{} Failed to parse source files: {}",
                "✗".red().bold(),
                e
            );
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

    // Step 2: Serialize IR to JSON
    pb.set_message("Serializing code graph...");

    let serialize_start = Instant::now();
    let ir_json = match serde_json::to_string(&ir) {
        Ok(json) => json,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!(
                "{} Failed to serialize IR: {}",
                "✗".red().bold(),
                e
            );
            return Ok(EXIT_CONFIG_ERROR);
        }
    };
    let serialize_ms = serialize_start.elapsed().as_millis() as u64;

    if args.verbose {
        eprintln!(
            "\n{} IR JSON size: {} bytes ({}ms)",
            "DEBUG".yellow(),
            ir_json.len(),
            serialize_ms
        );
    }
    
    // Debug: dump IR to file if UNFAULT_DUMP_IR is set
    if let Ok(dump_path) = std::env::var("UNFAULT_DUMP_IR") {
        if let Err(e) = std::fs::write(&dump_path, &ir_json) {
            eprintln!("{} Failed to dump IR to {}: {}", "DEBUG".yellow(), dump_path, e);
        } else {
            eprintln!("{} Dumped IR to {}", "DEBUG".yellow(), dump_path);
        }
    }

    // Step 3: Compute workspace ID
    let git_remote = get_git_remote(current_dir);
    let workspace_id_result = compute_workspace_id(
        git_remote.as_deref(),
        None, // No meta files in client-side parsing (could be added later)
        Some(workspace_label),
    );
    let workspace_id = workspace_id_result
        .as_ref()
        .map(|r| r.id.clone())
        .unwrap_or_else(|| format!("wks_{}", uuid::Uuid::new_v4().simple()));

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

    // Step 4: Send IR to API
    pb.set_message("Analyzing code graph...");

    // Build profiles from detected frameworks (e.g., "python_fastapi_backend", "go_gin_service")
    // The API resolves these profile IDs to specific rules
    let profiles: Vec<String> = workspace_info
        .to_workspace_descriptor()
        .profiles
        .iter()
        .map(|p| p.id.clone())
        .collect();

    if args.verbose {
        eprintln!(
            "\n{} Detected profiles: {:?}",
            "DEBUG".yellow(),
            profiles
        );
    }

    let api_start = Instant::now();
    let response = match api_client
        .analyze_ir(
            &config.api_key,
            &workspace_id,
            Some(&workspace_label),
            &profiles,
            ir_json,
        )
        .await
    {
        Ok(response) => response,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };
    let api_ms = api_start.elapsed().as_millis() as u64;

    pb.finish_and_clear();

    // Calculate elapsed time
    let elapsed = session_start.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;
    let engine_ms = response.elapsed_ms as u64;

    // Display review time with breakdown (include cache hit rate if meaningful)
    let cache_hit_rate = cache_stats.hit_rate();
    if cache_stats.hits > 0 || cache_stats.misses > 0 {
        eprintln!(
            "  Reviewed {} files in {}ms (parse: {}ms, api: {}ms, engine: {}ms, cache: {:.0}%) (trace: {})",
            file_count.to_string().bright_green(),
            elapsed_ms.to_string().bright_cyan(),
            parse_ms.to_string().dimmed(),
            api_ms.to_string().dimmed(),
            engine_ms.to_string().dimmed(),
            cache_hit_rate,
            &trace_id[..8].dimmed()
        );
    } else {
        eprintln!(
            "  Reviewed {} files in {}ms (parse: {}ms, api: {}ms, engine: {}ms) (trace: {})",
            file_count.to_string().bright_green(),
            elapsed_ms.to_string().bright_cyan(),
            parse_ms.to_string().dimmed(),
            api_ms.to_string().dimmed(),
            engine_ms.to_string().dimmed(),
            &trace_id[..8].dimmed()
        );
    }

    let finding_count = response.findings.len();
    
    if args.verbose {
        eprintln!(
            "\n{} Analysis response: {} findings from {} files",
            "DEBUG".yellow(),
            finding_count,
            response.file_count
        );
    }

    // Handle fix/dry-run mode
    let applied_patches = if args.fix || args.dry_run {
        apply_ir_patches(args, current_dir, &response.findings)?
    } else {
        0
    };

    // Display results
    display_ir_findings(args, &response.findings, applied_patches);

    if finding_count > 0 {
        Ok(EXIT_FINDINGS_FOUND)
    } else {
        Ok(EXIT_SUCCESS)
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
                if stats.modified_files.len() == 1 { "" } else { "s" }
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
            if stats.modified_files.len() == 1 { "" } else { "s" }
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

/// Display findings from IR analysis.
fn display_ir_findings(args: &ReviewArgs, findings: &[IrFinding], applied_patches: usize) {
    let total_findings = findings.len();

    if args.output_format == "json" {
        let output = serde_json::json!({
            "findings_count": total_findings,
            "findings": findings,
            "patches_applied": applied_patches,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    // Text output
    println!();

    if total_findings == 0 {
        println!(
            "{} No issues found! Your code looks good.",
            "✓".bright_green().bold()
        );
        return;
    }

    println!(
        "{} Found {} issue{}",
        "⚠".yellow().bold(),
        total_findings.to_string().bright_yellow(),
        if total_findings == 1 { "" } else { "s" }
    );
    println!();

    if args.output_mode == "full" {
        for finding in findings {
            display_ir_finding(finding);
        }
    } else {
        // Basic mode: grouped display
        display_ir_findings_grouped(findings);
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

        for (rule_id, rule_findings) in rules_by_id {
            let count = rule_findings.len();
            let title = &rule_findings[0].title;

            println!(
                "   [{}] {} ({}x)",
                rule_id.dimmed(),
                title,
                count.to_string().color("yellow")
            );
        }
    }
}

/// Execute review with server-side parsing (legacy mode).
///
/// This is the original implementation that sends source code to the server.
async fn execute_server_parse(
    args: &ReviewArgs,
    config: &Config,
    api_client: &ApiClient,
    trace_id: &str,
    current_dir: &std::path::Path,
    workspace_label: &str,
    dimensions: &[String],
    workspace_info: &crate::session::WorkspaceInfo,
    session_start: Instant,
) -> Result<i32> {
    // Create progress bar for API operations
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    // Step 2: Create session
    pb.set_message("Creating analysis session...");

    let runner = SessionRunner::new(api_client, &config.api_key);
    let session_response = match runner.create_session(workspace_info, None).await {
        Ok(response) => response,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };

    // Display subscription warning if present (non-blocking nudge)
    if let Some(warning) = &session_response.subscription_warning {
        display_subscription_warning(warning);
    }

    if args.verbose {
        eprintln!("\n{} Trace ID: {}", "DEBUG".yellow(), trace_id.cyan());
        eprintln!(
            "\n{} Session created: {}",
            "DEBUG".yellow(),
            serde_json::to_string_pretty(&session_response).unwrap_or_default()
        );
    }

    // Step 3: Collect files based on file hints
    pb.set_message("Collecting files for analysis...");

    let collector = FileCollector::new(current_dir);
    let collected_files = collector
        .collect(&session_response.file_hints, &workspace_info.source_files)
        .context("Failed to collect files")?;

    if args.verbose {
        eprintln!(
            "\n{} Collected {} files ({} bytes)",
            "DEBUG".yellow(),
            collected_files.files.len(),
            collected_files.total_bytes
        );
    }

    // Step 4: Run analysis
    pb.set_message("Running analysis...");

    let contexts: Vec<SessionContextInput> = dimensions
        .iter()
        .map(|dim| SessionContextInput {
            id: format!("ctx_{}", dim),
            label: dim.clone(),
            dimension: dim.clone(),
            files: collected_files.files.clone(),
        })
        .collect();

    let run_response = match runner
        .run_analysis_with_contexts(&session_response.session_id, workspace_info, contexts)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };

    pb.finish_and_clear();

    // Calculate elapsed time
    let elapsed = session_start.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;

    eprintln!(
        "  Reviewed in {}ms (trace: {})",
        elapsed_ms.to_string().bright_cyan(),
        &trace_id[..8].dimmed()
    );

    if args.verbose {
        eprintln!(
            "\n{} Analysis response: {}",
            "DEBUG".yellow(),
            serde_json::to_string_pretty(&run_response).unwrap_or_default()
        );
    }

    // Display results
    let total_findings: usize = run_response.contexts.iter().map(|c| c.findings.len()).sum();

    if args.output_format == "sarif" {
        let sarif = generate_sarif_output(&run_response, workspace_label);
        println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
    } else if args.output_format == "json" {
        let output = serde_json::json!({
            "session_id": run_response.session_id,
            "status": run_response.status,
            "findings_count": total_findings,
            "elapsed_ms": elapsed_ms,
            "contexts": run_response.contexts,
            "subscription_warning": run_response.subscription_warning,
            "is_limited": run_response.is_limited,
            "total_findings_count": run_response.total_findings_count,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!();

        if total_findings == 0 {
            if run_response.is_limited {
                if let Some(total) = run_response.total_findings_count {
                    if total > 0 {
                        println!(
                            "{} {} issue{} found (subscribe for full results)",
                            "⚠".yellow().bold(),
                            total.to_string().bright_yellow(),
                            if total == 1 { "" } else { "s" }
                        );
                    } else {
                        println!(
                            "{} No issues found! Your code looks good.",
                            "✓".bright_green().bold()
                        );
                    }
                } else {
                    println!(
                        "{} No issues found! Your code looks good.",
                        "✓".bright_green().bold()
                    );
                }
            } else {
                println!(
                    "{} No issues found! Your code looks good.",
                    "✓".bright_green().bold()
                );
            }
        } else {
            if run_response.is_limited {
                if let Some(total) = run_response.total_findings_count {
                    println!(
                        "{} Found {} issue{} (showing {} of {})",
                        "⚠".yellow().bold(),
                        total.to_string().bright_yellow(),
                        if total == 1 { "" } else { "s" },
                        total_findings,
                        total
                    );
                } else {
                    println!(
                        "{} Found {} issue{} (limited)",
                        "⚠".yellow().bold(),
                        total_findings.to_string().bright_yellow(),
                        if total_findings == 1 { "" } else { "s" }
                    );
                }
            } else {
                println!(
                    "{} Found {} issue{}",
                    "⚠".yellow().bold(),
                    total_findings.to_string().bright_yellow(),
                    if total_findings == 1 { "" } else { "s" }
                );
            }
            println!();

            let all_findings: Vec<&crate::api::Finding> = run_response
                .contexts
                .iter()
                .flat_map(|c| c.findings.iter())
                .collect();

            if args.output_mode == "full" {
                for finding in &all_findings {
                    display_finding(finding);
                }
            } else {
                display_findings_grouped(&all_findings);
            }

            if run_response.is_limited {
                if let Some(total) = run_response.total_findings_count {
                    display_limited_results_notice(total_findings, total);
                }
            }
        }

        if let Some(warning) = &run_response.subscription_warning {
            if session_response.subscription_warning.is_none() || run_response.is_limited {
                display_subscription_warning(warning);
            }
        }

        if let Some(graph_warning) = &run_response.graph_warning {
            eprintln!();
            eprintln!(
                "{} {} {}",
                "⚠".yellow(),
                "Graph Error:".yellow().bold(),
                graph_warning.dimmed()
            );
            eprintln!(
                "  {} RAG queries (unfault ask) will not work for this session.",
                "→".dimmed()
            );
        }
    }

    if total_findings > 0 {
        Ok(EXIT_FINDINGS_FOUND)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

/// Display findings grouped by severity and rule_id (for basic mode)
fn display_findings_grouped(findings: &[&crate::api::Finding]) {
    use std::collections::BTreeMap;

    // Define severity order (Critical first, then High, Medium, Low)
    let severity_order = |s: &str| -> u8 {
        match s {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            _ => 4,
        }
    };

    // Group findings by severity, then by rule_id
    // BTreeMap<severity_order, BTreeMap<rule_id, Vec<Finding>>>
    let mut grouped: BTreeMap<u8, BTreeMap<String, Vec<&crate::api::Finding>>> = BTreeMap::new();

    for finding in findings {
        let sev_key = severity_order(&finding.severity);
        grouped
            .entry(sev_key)
            .or_default()
            .entry(finding.rule_id.clone())
            .or_default()
            .push(*finding);
    }

    // Build a numbered rule index
    let mut rule_index: Vec<String> = Vec::new();
    for (_, rules_by_id) in &grouped {
        for (rule_id, _) in rules_by_id {
            if !rule_index.contains(rule_id) {
                rule_index.push(rule_id.clone());
            }
        }
    }

    // Display findings grouped by severity
    let mut first_severity = true;
    for (sev_key, rules_by_id) in &grouped {
        // Add blank line between severity groups (but not before the first one)
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

        // Count total findings for this severity
        let severity_count: usize = rules_by_id.values().map(|v| v.len()).sum();
        println!(
            "{} {} ({} issue{})",
            severity_icon,
            severity_name.color(severity_color).bold(),
            severity_count,
            if severity_count == 1 { "" } else { "s" }
        );

        for (rule_id, rule_findings) in rules_by_id {
            let count = rule_findings.len();
            let title = &rule_findings[0].title;

            println!(
                "   [{}] {} ({}x)",
                rule_id.dimmed(),
                title,
                count.to_string().color("yellow")
            );
        }
    }
}

/// Display a single finding (for full mode)
fn display_finding(finding: &crate::api::Finding) {
    let severity_color = match finding.severity.as_str() {
        "Critical" => "red",
        "High" => "red",
        "Medium" => "yellow",
        "Low" => "blue",
        _ => "white",
    };

    let severity_icon = match finding.severity.as_str() {
        "Critical" => "🔴",
        "High" => "🟠",
        "Medium" => "🟡",
        "Low" => "🔵",
        _ => "⚪",
    };

    println!(
        "{} {} [{}]",
        severity_icon,
        finding.title.bold(),
        finding.severity.color(severity_color)
    );

    println!("   {}", finding.description.dimmed());
    println!(
        "   Rule: {} | Dimension: {} | Confidence: {:.0}%",
        finding.rule_id.cyan(),
        finding.dimension,
        finding.confidence * 100.0
    );

    if let Some(diff) = &finding.diff {
        println!();
        println!("   {}", "Suggested fix:".green().bold());
        for line in diff.lines() {
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

/// Generate SARIF 2.1.0 output for GitHub Code Scanning and IDE integration
fn generate_sarif_output(
    run_response: &crate::api::SessionRunResponse,
    workspace_label: &str,
) -> serde_json::Value {
    use std::collections::HashMap;

    // Collect all findings and build rule registry
    let all_findings: Vec<&crate::api::Finding> = run_response
        .contexts
        .iter()
        .flat_map(|c| c.findings.iter())
        .collect();

    // Build unique rules map
    let mut rules_map: HashMap<String, &crate::api::Finding> = HashMap::new();
    for finding in &all_findings {
        rules_map.entry(finding.rule_id.clone()).or_insert(finding);
    }

    // Build SARIF rules array
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

            // Add help URL if we have a rule ID pattern
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

    // Build SARIF results array
    let results: Vec<serde_json::Value> = all_findings
        .iter()
        .map(|finding| {
            let mut result = serde_json::json!({
                "ruleId": finding.rule_id,
                "level": severity_to_sarif_level(&finding.severity),
                "message": {
                    "text": finding.description
                },
                "properties": {
                    "confidence": finding.confidence,
                    "dimension": finding.dimension,
                    "kind": finding.kind
                }
            });

            // Add location if available
            if let Some(location) = &finding.location {
                let mut region = serde_json::json!({
                    "startLine": location.start_line
                });

                if let Some(end_line) = location.end_line {
                    region["endLine"] = serde_json::json!(end_line);
                }
                if let Some(start_col) = location.start_column {
                    region["startColumn"] = serde_json::json!(start_col);
                }
                if let Some(end_col) = location.end_column {
                    region["endColumn"] = serde_json::json!(end_col);
                }

                if let Some(obj) = result.as_object_mut() {
                    obj.insert(
                        "locations".to_string(),
                        serde_json::json!([{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": location.file,
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": region
                            }
                        }]),
                    );
                }
            }

            // Add fix if diff is available
            if let Some(diff) = &finding.diff {
                if let Some(location) = &finding.location {
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert(
                            "fixes".to_string(),
                            serde_json::json!([{
                                "description": {
                                    "text": "Apply suggested fix"
                                },
                                "artifactChanges": [{
                                    "artifactLocation": {
                                        "uri": location.file,
                                        "uriBaseId": "%SRCROOT%"
                                    },
                                    "replacements": [{
                                        "deletedRegion": {
                                            "startLine": location.start_line,
                                            "endLine": location.end_line.unwrap_or(location.start_line)
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

    // Build complete SARIF document
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
    match severity {
        "Critical" | "High" => "error",
        "Medium" => "warning",
        "Low" | "Info" => "note",
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
    fn test_display_finding_does_not_panic() {
        let finding = crate::api::Finding {
            id: "test_001".to_string(),
            rule_id: "test.rule".to_string(),
            kind: "BehaviorThreat".to_string(),
            title: "Test Finding".to_string(),
            description: "This is a test finding".to_string(),
            severity: "Medium".to_string(),
            confidence: 0.85,
            dimension: "Stability".to_string(),
            location: None,
            diff: None,
            fix_preview: None,
        };
        display_finding(&finding);
    }

    #[test]
    fn test_display_findings_grouped_does_not_panic() {
        let findings = vec![
            crate::api::Finding {
                id: "test_001".to_string(),
                rule_id: "http.timeout".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Missing HTTP timeout".to_string(),
                description: "HTTP call without timeout".to_string(),
                severity: "High".to_string(),
                confidence: 0.9,
                dimension: "Stability".to_string(),
                location: None,
                diff: None,
                fix_preview: None,
            },
            crate::api::Finding {
                id: "test_002".to_string(),
                rule_id: "http.timeout".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Missing HTTP timeout".to_string(),
                description: "Another HTTP call without timeout".to_string(),
                severity: "High".to_string(),
                confidence: 0.9,
                dimension: "Stability".to_string(),
                location: None,
                diff: None,
                fix_preview: None,
            },
            crate::api::Finding {
                id: "test_003".to_string(),
                rule_id: "cors.missing".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Missing CORS".to_string(),
                description: "No CORS configured".to_string(),
                severity: "Medium".to_string(),
                confidence: 0.85,
                dimension: "Correctness".to_string(),
                location: None,
                diff: None,
                fix_preview: None,
            },
            crate::api::Finding {
                id: "test_004".to_string(),
                rule_id: "critical.issue".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Critical Issue".to_string(),
                description: "A critical issue".to_string(),
                severity: "Critical".to_string(),
                confidence: 0.95,
                dimension: "Stability".to_string(),
                location: None,
                diff: None,
                fix_preview: None,
            },
        ];
        let refs: Vec<&crate::api::Finding> = findings.iter().collect();
        display_findings_grouped(&refs);
    }

    #[test]
    fn test_sarif_output_generation() {
        let run_response = crate::api::SessionRunResponse {
            session_id: "test_session".to_string(),
            status: "completed".to_string(),
            meta: serde_json::json!({}),
            contexts: vec![crate::api::ContextResult {
                context_id: "ctx_1".to_string(),
                label: "Test".to_string(),
                findings: vec![crate::api::Finding {
                    id: "finding_001".to_string(),
                    rule_id: "python.http.missing_timeout".to_string(),
                    kind: "BehaviorThreat".to_string(),
                    title: "Missing HTTP timeout".to_string(),
                    description: "HTTP request without timeout".to_string(),
                    severity: "High".to_string(),
                    confidence: 0.9,
                    dimension: "Stability".to_string(),
                    location: Some(crate::api::FindingLocation {
                        file: "src/main.py".to_string(),
                        start_line: 10,
                        end_line: Some(12),
                        start_column: Some(5),
                        end_column: Some(40),
                    }),
                    diff: Some("--- a/src/main.py\n+++ b/src/main.py\n@@ -10,1 +10,1 @@\n-requests.get(url)\n+requests.get(url, timeout=30)".to_string()),
                    fix_preview: None,
                }],
            }],
            elapsed_ms: 100,
            error_message: None,
            subscription_warning: None,
            is_limited: false,
            total_findings_count: None,
            graph_warning: None,
        };

        let sarif = generate_sarif_output(&run_response, "test-workspace");

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
    fn test_display_findings_grouped_empty() {
        let findings: Vec<&crate::api::Finding> = vec![];
        display_findings_grouped(&findings);
    }
}

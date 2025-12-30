//! # Graph Command
//!
//! Implements the graph command for querying the code graph.
//!
//! Note: The code graph is automatically built when you run `unfault review`.
//! These commands query the graph that was built during the last review session.
//!
//! ## Usage
//!
//! ```bash
//! # First, run review to build the graph (with functions, classes, calls)
//! unfault review
//!
//! # Impact analysis: "What breaks if I change this file?"
//! # Workspace auto-detected from current directory
//! unfault graph impact auth/middleware.py
//!
//! # Or specify a workspace explicitly
//! unfault graph impact auth/middleware.py --workspace /path/to/project
//!
//! # Find files using a library
//! unfault graph library requests
//!
//! # Find external dependencies for a file
//! unfault graph deps main.py
//!
//! # Find the most critical files in the codebase
//! unfault graph critical --limit 10
//!
//! # Get graph statistics
//! unfault graph stats
//!
//! # Override with session ID (advanced usage)
//! unfault graph stats --session abc123
//! ```

use anyhow::Result;
use colored::Colorize;
use std::path::Path;

use crate::api::ApiClient;
use crate::api::graph::{
    CentralityRequest, CentralityResponse, DependencyQueryRequest, DependencyQueryResponse,
    FunctionImpactRequest, GraphStatsResponse, ImpactAnalysisRequest, ImpactAnalysisResponse,
};
use crate::config::Config;
use crate::exit_codes::*;
use crate::session::{MetaFileInfo, compute_workspace_id, get_git_remote};

/// Arguments for the graph impact command
#[derive(Debug)]
pub struct ImpactArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// File path to analyze
    pub file_path: String,
    /// Maximum depth for transitive import analysis
    pub max_depth: i32,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph library command (files using a library)
#[derive(Debug)]
pub struct LibraryArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Library name to search for
    pub library_name: String,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph deps command (external dependencies of a file)
#[derive(Debug)]
pub struct DepsArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// File path to analyze
    pub file_path: String,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph critical command (centrality analysis)
#[derive(Debug)]
pub struct CriticalArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Maximum number of files to return
    pub limit: i32,
    /// Metric to sort by
    pub sort_by: String,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

#[derive(Debug)]
pub struct FunctionImpactArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Function in format file:function
    pub function: String,
    /// Maximum depth for transitive call analysis
    pub max_depth: i32,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph stats command
#[derive(Debug)]
pub struct StatsArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

// =============================================================================
// Workspace ID Resolution
// =============================================================================

/// Resolved identifier for graph queries
#[derive(Debug)]
enum ResolvedIdentifier {
    SessionId(String),
    WorkspaceId(String),
}

/// Auto-detect workspace ID from a directory
fn detect_workspace_id(workspace_path: &Path, verbose: bool) -> Option<String> {
    // Try git remote first
    let git_remote = get_git_remote(workspace_path);

    // Try to find manifest files
    let mut meta_files = Vec::new();

    // Check pyproject.toml
    let pyproject_path = workspace_path.join("pyproject.toml");
    if pyproject_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&pyproject_path) {
            meta_files.push(MetaFileInfo {
                kind: "pyproject",
                contents,
            });
        }
    }

    // Check package.json
    let package_json_path = workspace_path.join("package.json");
    if package_json_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&package_json_path) {
            meta_files.push(MetaFileInfo {
                kind: "package_json",
                contents,
            });
        }
    }

    // Check Cargo.toml
    let cargo_toml_path = workspace_path.join("Cargo.toml");
    if cargo_toml_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&cargo_toml_path) {
            meta_files.push(MetaFileInfo {
                kind: "cargo_toml",
                contents,
            });
        }
    }

    // Check go.mod
    let go_mod_path = workspace_path.join("go.mod");
    if go_mod_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&go_mod_path) {
            meta_files.push(MetaFileInfo {
                kind: "go_mod",
                contents,
            });
        }
    }

    // Use workspace folder name as fallback label
    let label = workspace_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    // Compute workspace ID
    let result = compute_workspace_id(
        git_remote.as_deref(),
        if meta_files.is_empty() {
            None
        } else {
            Some(&meta_files)
        },
        label.as_deref(),
    );

    if let Some(ref wks) = result {
        if verbose {
            eprintln!(
                "  {} Workspace ID: {} (source: {:?})",
                "→".dimmed(),
                wks.id,
                wks.source
            );
        }
    }

    result.map(|r| r.id)
}

/// Resolve session_id or workspace_id based on provided arguments
fn resolve_identifier(
    session_id: Option<&str>,
    workspace_path: Option<&str>,
    verbose: bool,
) -> Result<ResolvedIdentifier, i32> {
    // If session_id is explicitly provided, use it
    if let Some(sid) = session_id {
        return Ok(ResolvedIdentifier::SessionId(sid.to_string()));
    }

    // Otherwise, auto-detect workspace_id
    let path = match workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir().map_err(|e| {
            eprintln!(
                "{} Failed to get current directory: {}",
                "Error:".red().bold(),
                e
            );
            EXIT_ERROR
        })?,
    };

    if verbose {
        eprintln!(
            "{} Auto-detecting workspace from: {}",
            "→".cyan(),
            path.display()
        );
    }

    match detect_workspace_id(&path, verbose) {
        Some(wks_id) => Ok(ResolvedIdentifier::WorkspaceId(wks_id)),
        None => {
            eprintln!(
                "{} Could not determine workspace identity.",
                "Error:".red().bold()
            );
            eprintln!(
                "  {} Try running from a git repository, or a directory with pyproject.toml,",
                "Hint:".yellow()
            );
            eprintln!("        package.json, Cargo.toml, or go.mod.");
            eprintln!("        Or specify --session <ID> to use a specific session.");
            Err(EXIT_CONFIG_ERROR)
        }
    }
}

/// Execute the graph impact command
///
/// Shows what files would be affected by changes to a specific file.
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Analysis completed successfully
/// * `Ok(EXIT_CONFIG_ERROR)` - Not logged in or configuration error
/// * `Ok(EXIT_AUTH_ERROR)` - API key is invalid
/// * `Ok(EXIT_NETWORK_ERROR)` - Cannot reach the API
pub async fn execute_impact(args: ImpactArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} Not logged in. Run `unfault login` first.",
                "Error:".red().bold()
            );
            if args.verbose {
                eprintln!("  {}: {}", "Details".dimmed(), e);
            }
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Resolve session_id or workspace_id
    let identifier = match resolve_identifier(
        args.session_id.as_deref(),
        args.workspace_path.as_deref(),
        args.verbose,
    ) {
        Ok(id) => id,
        Err(exit_code) => return Ok(exit_code),
    };

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Build request based on resolved identifier
    let (session_id, workspace_id) = match identifier {
        ResolvedIdentifier::SessionId(sid) => (Some(sid), None),
        ResolvedIdentifier::WorkspaceId(wid) => (None, Some(wid)),
    };

    let request = ImpactAnalysisRequest {
        session_id,
        workspace_id,
        file_path: args.file_path.clone(),
        max_depth: args.max_depth,
    };

    if args.verbose {
        eprintln!("{} Analyzing impact of: {}", "→".cyan(), args.file_path);
    }

    // Execute query
    let response = match api_client.graph_impact(&config.api_key, &request).await {
        Ok(response) => response,
        Err(e) => {
            return handle_api_error(e, &config, args.verbose);
        }
    };

    // Output results
    if args.json {
        output_impact_json(&response)?;
    } else {
        output_impact_formatted(&response, args.verbose);
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph library command
///
/// Shows files that use a specific library.
pub async fn execute_library(args: LibraryArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} Not logged in. Run `unfault login` first.",
                "Error:".red().bold()
            );
            if args.verbose {
                eprintln!("  {}: {}", "Details".dimmed(), e);
            }
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Resolve session_id or workspace_id
    let identifier = match resolve_identifier(
        args.session_id.as_deref(),
        args.workspace_path.as_deref(),
        args.verbose,
    ) {
        Ok(id) => id,
        Err(exit_code) => return Ok(exit_code),
    };

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Build request based on resolved identifier
    let (session_id, workspace_id) = match identifier {
        ResolvedIdentifier::SessionId(sid) => (Some(sid), None),
        ResolvedIdentifier::WorkspaceId(wid) => (None, Some(wid)),
    };

    let request = DependencyQueryRequest {
        session_id,
        workspace_id,
        query_type: "files_using_library".to_string(),
        library_name: Some(args.library_name.clone()),
        file_path: None,
    };

    if args.verbose {
        eprintln!("{} Finding files using: {}", "→".cyan(), args.library_name);
    }

    // Execute query
    let response = match api_client
        .graph_dependencies(&config.api_key, &request)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return handle_api_error(e, &config, args.verbose);
        }
    };

    // Output results
    if args.json {
        output_deps_json(&response)?;
    } else {
        output_library_formatted(&response, &args.library_name, args.verbose);
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph deps command
///
/// Shows external dependencies of a file.
pub async fn execute_deps(args: DepsArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} Not logged in. Run `unfault login` first.",
                "Error:".red().bold()
            );
            if args.verbose {
                eprintln!("  {}: {}", "Details".dimmed(), e);
            }
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Resolve session_id or workspace_id
    let identifier = match resolve_identifier(
        args.session_id.as_deref(),
        args.workspace_path.as_deref(),
        args.verbose,
    ) {
        Ok(id) => id,
        Err(exit_code) => return Ok(exit_code),
    };

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Build request based on resolved identifier
    let (session_id, workspace_id) = match identifier {
        ResolvedIdentifier::SessionId(sid) => (Some(sid), None),
        ResolvedIdentifier::WorkspaceId(wid) => (None, Some(wid)),
    };

    let request = DependencyQueryRequest {
        session_id,
        workspace_id,
        query_type: "external_dependencies".to_string(),
        library_name: None,
        file_path: Some(args.file_path.clone()),
    };

    if args.verbose {
        eprintln!("{} Finding dependencies of: {}", "→".cyan(), args.file_path);
    }

    // Execute query
    let response = match api_client
        .graph_dependencies(&config.api_key, &request)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return handle_api_error(e, &config, args.verbose);
        }
    };

    // Output results
    if args.json {
        output_deps_json(&response)?;
    } else {
        output_deps_formatted(&response, &args.file_path, args.verbose);
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph critical command
///
/// Shows the most critical/hub files in the codebase.
pub async fn execute_critical(args: CriticalArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} Not logged in. Run `unfault login` first.",
                "Error:".red().bold()
            );
            if args.verbose {
                eprintln!("  {}: {}", "Details".dimmed(), e);
            }
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Resolve session_id or workspace_id
    let identifier = match resolve_identifier(
        args.session_id.as_deref(),
        args.workspace_path.as_deref(),
        args.verbose,
    ) {
        Ok(id) => id,
        Err(exit_code) => return Ok(exit_code),
    };

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Build request based on resolved identifier
    let (session_id, workspace_id) = match identifier {
        ResolvedIdentifier::SessionId(sid) => (Some(sid), None),
        ResolvedIdentifier::WorkspaceId(wid) => (None, Some(wid)),
    };

    let request = CentralityRequest {
        session_id,
        workspace_id,
        limit: args.limit,
        sort_by: args.sort_by.clone(),
    };

    if args.verbose {
        eprintln!(
            "{} Finding top {} critical files (sorted by {})",
            "→".cyan(),
            args.limit,
            args.sort_by
        );
    }

    // Execute query
    let response = match api_client.graph_centrality(&config.api_key, &request).await {
        Ok(response) => response,
        Err(e) => {
            return handle_api_error(e, &config, args.verbose);
        }
    };

    // Output results
    if args.json {
        output_critical_json(&response)?;
    } else {
        output_critical_formatted(&response, args.verbose);
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph stats command
///
/// Shows statistics about the code graph.
pub async fn execute_stats(args: StatsArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} Not logged in. Run `unfault login` first.",
                "Error:".red().bold()
            );
            if args.verbose {
                eprintln!("  {}: {}", "Details".dimmed(), e);
            }
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Resolve session_id or workspace_id
    let identifier = match resolve_identifier(
        args.session_id.as_deref(),
        args.workspace_path.as_deref(),
        args.verbose,
    ) {
        Ok(id) => id,
        Err(exit_code) => return Ok(exit_code),
    };

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Execute query based on resolved identifier
    let response = match identifier {
        ResolvedIdentifier::SessionId(sid) => {
            if args.verbose {
                eprintln!(
                    "{} Getting graph statistics for session: {}",
                    "→".cyan(),
                    sid
                );
            }
            api_client.graph_stats(&config.api_key, &sid).await
        }
        ResolvedIdentifier::WorkspaceId(wid) => {
            if args.verbose {
                eprintln!(
                    "{} Getting graph statistics for workspace: {}",
                    "→".cyan(),
                    wid
                );
            }
            api_client
                .graph_stats_by_workspace(&config.api_key, &wid)
                .await
        }
    };

    let response = match response {
        Ok(response) => response,
        Err(e) => {
            return handle_api_error(e, &config, args.verbose);
        }
    };

    // Output results
    if args.json {
        output_stats_json(&response)?;
    } else {
        output_stats_formatted(&response, args.verbose);
    }

    Ok(EXIT_SUCCESS)
}

// =============================================================================
// Error Handling
// =============================================================================

fn handle_api_error(e: crate::api::ApiError, config: &Config, verbose: bool) -> Result<i32> {
    if e.is_auth_error() {
        eprintln!(
            "{} Authentication failed. Run `unfault login` to re-authenticate.",
            "Error:".red().bold()
        );
        if verbose {
            eprintln!("  {}: {}", "Details".dimmed(), e);
            eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
        }
        return Ok(EXIT_AUTH_ERROR);
    }
    if e.is_network_error() {
        eprintln!(
            "{} Cannot reach the API. Check your internet connection.",
            "Error:".red().bold()
        );
        if verbose {
            eprintln!("  {}: {}", "Details".dimmed(), e);
            eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
        }
        return Ok(EXIT_NETWORK_ERROR);
    }
    if e.is_server_error() {
        eprintln!("{} {}", "Error:".red().bold(), e);
        if verbose {
            eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
        }
        return Ok(EXIT_SERVICE_UNAVAILABLE);
    }
    eprintln!("{} {}", "Error:".red().bold(), e);
    if verbose {
        eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
    }
    Ok(EXIT_ERROR)
}

// =============================================================================
// Output Formatting
// =============================================================================

fn output_impact_json(response: &ImpactAnalysisResponse) -> Result<()> {
    let json = serde_json::to_string_pretty(response)?;
    println!("{}", json);
    Ok(())
}

fn output_impact_formatted(response: &ImpactAnalysisResponse, verbose: bool) {
    println!();
    println!(
        "{} {} {}",
        "🔍".cyan(),
        "Impact Analysis:".bold(),
        response.file_path.bright_white()
    );
    println!();

    if response.total_affected == 0 {
        println!(
            "  {} This file is a leaf node — no other files depend on it.",
            "ℹ".blue()
        );
        println!(
            "  {} Changes here are isolated and safe to refactor.",
            "".dimmed()
        );
        println!();
        return;
    }

    // Summary with context
    let direct_count = response.direct_importers.len();
    let transitive_only: Vec<_> = response
        .transitive_importers
        .iter()
        .filter(|f| f.depth.unwrap_or(1) > 1)
        .collect();
    let transitive_count = transitive_only.len();

    println!(
        "  {} This file is imported by {} file(s)",
        "→".cyan(),
        response.total_affected.to_string().bold()
    );
    if transitive_count > 0 {
        println!(
            "  {} {} direct, {} through transitive imports",
            "".dimmed(),
            direct_count,
            transitive_count
        );
    }
    println!();

    // Direct importers
    if !response.direct_importers.is_empty() {
        println!("{}", "Direct Dependencies".bold().underline());
        println!(
            "{}",
            "Files that import this directly — changes here affect them first"
                .dimmed()
        );
        println!("{}", "─".repeat(60).dimmed());
        for file in &response.direct_importers {
            let lang = file.language.as_deref().unwrap_or("?");
            println!(
                "  {} {} {}",
                "•".cyan(),
                file.path.bright_white(),
                format!("[{}]", lang).dimmed()
            );
        }
        println!();
    }

    // Transitive importers (if different from direct)
    if !transitive_only.is_empty() {
        println!("{}", "Transitive Dependencies".bold().underline());
        println!(
            "{}",
            "Files that depend on this indirectly — ripple effects"
                .dimmed()
        );
        println!("{}", "─".repeat(60).dimmed());
        for file in &transitive_only {
            let lang = file.language.as_deref().unwrap_or("?");
            let depth = file.depth.unwrap_or(0);
            let depth_indicator = "→".repeat(depth as usize);
            println!(
                "  {} {} {} {}",
                depth_indicator.dimmed(),
                file.path.bright_white(),
                format!("[{}]", lang).dimmed(),
                format!("({} hops)", depth).dimmed()
            );
        }
        println!();
    }

    // Actionable insight
    if response.total_affected >= 5 {
        println!(
            "  {} This is a hub file. Consider extra care when modifying.",
            "💡".yellow()
        );
        println!();
    }

    if verbose {
        println!(
            "  {} Direct: {}, Transitive: {}, Total: {}",
            "Stats:".dimmed(),
            direct_count,
            transitive_count,
            response.total_affected
        );
        println!();
    }
}

fn output_deps_json(response: &DependencyQueryResponse) -> Result<()> {
    let json = serde_json::to_string_pretty(response)?;
    println!("{}", json);
    Ok(())
}

fn output_library_formatted(
    response: &DependencyQueryResponse,
    library_name: &str,
    verbose: bool,
) {
    println!();
    println!(
        "{} {} {}",
        "📚".cyan(),
        "Library Usage:".bold(),
        library_name.bright_white()
    );
    println!();

    if let Some(files) = &response.files {
        if files.is_empty() {
            println!(
                "  {} '{}' is not used directly in any files.",
                "ℹ".blue(),
                library_name
            );
            println!(
                "  {} It may be a transitive dependency or not imported yet.",
                "".dimmed()
            );
        } else {
            println!(
                "  {} '{}' is used in {} file(s)",
                "→".cyan(),
                library_name,
                files.len().to_string().bold()
            );
            println!();
            println!("{}", "Usage Locations".bold().underline());
            println!(
                "{}",
                "These files import this library directly".dimmed()
            );
            println!("{}", "─".repeat(60).dimmed());
            for file in files {
                let lang = file.language.as_deref().unwrap_or("?");
                println!(
                    "  {} {} {}",
                    "•".cyan(),
                    file.path.bright_white(),
                    format!("[{}]", lang).dimmed()
                );
            }

            // Provide context based on file count
            if files.len() >= 10 {
                println!();
                println!(
                    "  {} This library is used widely. Consider its stability and versioning.",
                    "💡".yellow()
                );
            }
        }
    } else {
        println!("  {} No usage data available", "ℹ".blue());
    }
    println!();

    if verbose {
        println!(
            "  {} Use 'unfault graph deps <file>' to see all dependencies in a specific file.",
            "Tip:".dimmed()
        );
        println!();
    }
}

fn output_deps_formatted(response: &DependencyQueryResponse, file_path: &str, verbose: bool) {
    println!();
    println!(
        "{} {} {}",
        "📦".cyan(),
        "External Dependencies:".bold(),
        file_path.bright_white()
    );
    println!();

    if let Some(deps) = &response.dependencies {
        if deps.is_empty() {
            println!(
                "  {} This file doesn't import any external libraries directly.",
                "ℹ".blue()
            );
            println!(
                "  {} It may use standard library modules or local imports only.",
                "".dimmed()
            );
        } else {
            // Group dependencies by category
            let mut by_category: std::collections::HashMap<&str, Vec<&crate::api::graph::ExternalModuleInfo>> =
                std::collections::HashMap::new();
            for dep in deps {
                let category = dep.category.as_deref().unwrap_or("Other");
                by_category.entry(category).or_default().push(dep);
            }

            println!(
                "  {} This file uses {} external {} across {} {}",
                "→".cyan(),
                deps.len().to_string().bold(),
                if deps.len() == 1 { "library" } else { "libraries" },
                by_category.len(),
                if by_category.len() == 1 { "category" } else { "categories" }
            );
            println!();

            println!("{}", "By Category".bold().underline());
            println!(
                "{}",
                "Understanding what external code this file relies on".dimmed()
            );
            println!("{}", "─".repeat(60).dimmed());

            // Order categories by importance
            let category_order = [
                "HttpClient",
                "Database",
                "WebFramework",
                "AsyncRuntime",
                "Logging",
                "Resilience",
                "Other",
            ];

            for category in category_order {
                if let Some(category_deps) = by_category.get(category) {
                    let category_label = match category {
                        "HttpClient" => "🌐 HTTP/Network",
                        "Database" => "🗄️  Database",
                        "WebFramework" => "🖥️  Web Framework",
                        "AsyncRuntime" => "⚡ Async Runtime",
                        "Logging" => "📝 Logging",
                        "Resilience" => "🛡️  Resilience",
                        _ => "📦 Other",
                    };

                    println!("  {}", category_label.bold());
                    for dep in category_deps {
                        println!("    {} {}", "•".dimmed(), dep.name.bright_white());
                    }
                }
            }

            // Show any categories not in our predefined order
            for (category, category_deps) in &by_category {
                if !category_order.contains(category) {
                    println!("  {} {}", "📦".dimmed(), category.bold());
                    for dep in category_deps {
                        println!("    {} {}", "•".dimmed(), dep.name.bright_white());
                    }
                }
            }

            // Provide insights
            if deps.len() >= 8 {
                println!();
                println!(
                    "  {} This file has many dependencies. Consider if all are needed.",
                    "💡".yellow()
                );
            }
            if by_category.contains_key("HttpClient") && !by_category.contains_key("Resilience") {
                println!();
                println!(
                    "  {} Uses HTTP but has no resilience libraries (retry, circuit breaker).",
                    "💡".yellow()
                );
            }
        }
    } else {
        println!("  {} Dependency information not available", "ℹ".blue());
    }
    println!();

    if verbose {
        println!(
            "  {} Use 'unfault graph library <name>' to find all files using a specific library.",
            "Tip:".dimmed()
        );
        println!();
    }
}

fn output_critical_json(response: &CentralityResponse) -> Result<()> {
    let json = serde_json::to_string_pretty(response)?;
    println!("{}", json);
    Ok(())
}

fn output_critical_formatted(response: &CentralityResponse, verbose: bool) {
    println!();
    println!(
        "{} {}",
        "🎯".cyan(),
        "Hub Files Analysis".bold()
    );
    println!(
        "{}",
        "Files with the most connections — changes here have the widest impact".dimmed()
    );
    println!();

    if response.files.is_empty() {
        println!("  {} No files analyzed yet. Run 'unfault review' first.", "ℹ".blue());
        println!();
        return;
    }

    println!(
        "  {} Analyzing {} files, showing top {}",
        "→".cyan(),
        response.total_files,
        response.files.len()
    );
    println!();

    // Header
    println!(
        "{}",
        format!(
            "  {:3} {:40} {:>6} {:>6} {:>6} {:>8}",
            "#", "File", "In", "Out", "Libs", "Score"
        )
        .bold()
    );
    println!("  {}", "─".repeat(75).dimmed());

    for (i, file) in response.files.iter().enumerate() {
        let rank = i + 1;
        let path = if file.path.len() > 38 {
            format!("...{}", &file.path[file.path.len() - 35..])
        } else {
            file.path.clone()
        };

        // Color-code the importance score with context
        let score_str = file.importance_score.to_string();
        let score_colored = if file.importance_score >= 20 {
            score_str.red().bold()
        } else if file.importance_score >= 10 {
            score_str.yellow()
        } else {
            score_str.normal()
        };

        println!(
            "  {:3} {:40} {:>6} {:>6} {:>6} {:>8}",
            format!("{}", rank).dimmed(),
            path.bright_white(),
            file.in_degree.to_string().cyan(),
            file.out_degree.to_string().blue(),
            file.library_usage.to_string().green(),
            score_colored
        );

        if verbose {
            // Provide context for high-impact files
            if file.in_degree >= 5 {
                println!(
                    "      {} {} files depend on this — changes ripple widely",
                    "└".dimmed(),
                    file.in_degree
                );
            }
        }
    }
    println!();

    // Insights
    if let Some(top) = response.files.first() {
        if top.importance_score >= 20 {
            println!(
                "  {} '{}' is a major hub. Consider extra review for changes.",
                "💡".yellow(),
                top.path.split('/').last().unwrap_or(&top.path)
            );
            println!();
        }
    }

    // Legend
    println!(
        "  {} In: dependents | Out: dependencies | Libs: external packages",
        "Legend:".dimmed()
    );
    println!(
        "  {} Higher score = more central to the codebase",
        "".dimmed()
    );
    println!();

    if verbose {
        println!(
            "  {} Use 'unfault graph impact <file>' to see full dependency details.",
            "Tip:".dimmed()
        );
        println!();
    }
}

fn output_stats_json(response: &GraphStatsResponse) -> Result<()> {
    let json = serde_json::to_string_pretty(response)?;
    println!("{}", json);
    Ok(())
}

pub async fn execute_function_impact(args: FunctionImpactArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} Not logged in. Run `unfault login` first.",
                "Error:".red().bold()
            );
            if args.verbose {
                eprintln!("  {}: {}", "Details".dimmed(), e);
            }
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Resolve session_id or workspace_id
    let identifier = match resolve_identifier(
        args.session_id.as_deref(),
        args.workspace_path.as_deref(),
        args.verbose,
    ) {
        Ok(id) => id,
        Err(exit_code) => return Ok(exit_code),
    };

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Parse function argument (file:function)
    let (file_path, function_name) = match args.function.split_once(':') {
        Some((file, func)) => (file.to_string(), func.to_string()),
        None => {
            eprintln!(
                "{} Function must be in format file:function (e.g., main.py:process_user)",
                "Error:".red().bold()
            );
            return Ok(EXIT_ERROR);
        }
    };

    // Build request based on resolved identifier
    let (session_id, workspace_id) = match identifier {
        ResolvedIdentifier::SessionId(sid) => (Some(sid), None),
        ResolvedIdentifier::WorkspaceId(wid) => (None, Some(wid)),
    };

    let request = FunctionImpactRequest {
        session_id,
        workspace_id,
        file_path,
        function_name,
        max_depth: args.max_depth,
    };

    if args.verbose {
        eprintln!(
            "{} Analyzing impact of: {}:{}",
            "→".cyan(),
            request.file_path,
            request.function_name
        );
    }

    // Execute query
    let response = match api_client
        .graph_function_impact(&config.api_key, &request)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return handle_api_error(e, &config, args.verbose);
        }
    };

    // Output results
    if args.json {
        let json = serde_json::to_string_pretty(&response)?;
        println!("{}", json);
    } else {
        println!();
        println!(
            "{} {} {}",
            "🔗".cyan(),
            "Function Call Graph:".bold(),
            response.function.bright_white()
        );
        println!();

        if response.total_affected == 0 {
            println!(
                "  {} This function is a leaf — not called by any other functions.",
                "ℹ".blue()
            );
            println!(
                "  {} Safe to refactor without affecting other call paths.",
                "".dimmed()
            );
            println!();
            return Ok(EXIT_SUCCESS);
        }

        // Calculate direct vs transitive
        let direct_count = response.direct_callers.len();
        let transitive_only: Vec<_> = response
            .transitive_callers
            .iter()
            .filter(|c| c.depth > 1)
            .collect();
        let transitive_count = transitive_only.len();

        println!(
            "  {} This function is called from {} place(s)",
            "→".cyan(),
            response.total_affected.to_string().bold()
        );
        if transitive_count > 0 {
            println!(
                "  {} {} direct, {} through call chains",
                "".dimmed(),
                direct_count,
                transitive_count
            );
        }
        println!();

        // Direct callers
        if !response.direct_callers.is_empty() {
            println!("{}", "Direct Callers".bold().underline());
            println!(
                "{}",
                "Functions that call this directly".dimmed()
            );
            println!("{}", "─".repeat(60).dimmed());
            for caller in &response.direct_callers {
                println!(
                    "  {} {} ({})",
                    "•".cyan(),
                    caller.function.bright_white(),
                    caller.path.dimmed()
                );
            }
            println!();
        }

        // Transitive callers
        if !transitive_only.is_empty() {
            println!("{}", "Upstream Callers".bold().underline());
            println!(
                "{}",
                "Functions that depend on this through call chains".dimmed()
            );
            println!("{}", "─".repeat(60).dimmed());
            for caller in transitive_only {
                let depth_indicator = "→".repeat(caller.depth as usize);
                println!(
                    "  {} {} ({}) {}",
                    depth_indicator.dimmed(),
                    caller.function.bright_white(),
                    caller.path.dimmed(),
                    format!("({} hops)", caller.depth).dimmed()
                );
            }
            println!();
        }

        // Insights
        if response.total_affected >= 5 {
            println!(
                "  {} This is a core function. Changes affect many call paths.",
                "💡".yellow()
            );
            println!();
        }

        if args.verbose {
            println!(
                "  {} Direct: {}, Upstream: {}, Total: {}",
                "Stats:".dimmed(),
                direct_count,
                transitive_count,
                response.total_affected
            );
            println!();
        }
    }

    Ok(EXIT_SUCCESS)
}

fn output_stats_formatted(response: &GraphStatsResponse, verbose: bool) {
    println!();
    println!("{} {}", "🗺️".cyan(), "Code Graph Overview".bold());
    println!(
        "{}",
        "A map of your codebase structure and connections".dimmed()
    );
    println!();

    // Summary line
    let total_code_units = response.function_count + response.class_count;
    println!(
        "  {} {} code units across {} files",
        "→".cyan(),
        total_code_units.to_string().bold(),
        response.file_count.to_string().bold()
    );
    println!();

    // Nodes section with context
    println!("{}", "Structure".bold().underline());
    println!("{}", "─".repeat(45).dimmed());
    println!(
        "  {:28} {:>12}",
        "📄 Files".bright_white(),
        response.file_count.to_string().cyan()
    );
    println!(
        "  {:28} {:>12}",
        "⚙️  Functions".bright_white(),
        response.function_count.to_string().cyan()
    );
    println!(
        "  {:28} {:>12}",
        "📦 Classes".bright_white(),
        response.class_count.to_string().cyan()
    );
    println!(
        "  {:28} {:>12}",
        "📚 External Libraries".bright_white(),
        response.external_module_count.to_string().cyan()
    );
    println!("{}", "─".repeat(45).dimmed());
    println!(
        "  {:28} {:>12}",
        "Total nodes".bold(),
        response.total_nodes.to_string().bold().cyan()
    );
    println!();

    // Connections section with context
    println!("{}", "Connections".bold().underline());
    println!("{}", "─".repeat(45).dimmed());
    println!(
        "  {:28} {:>12}",
        "🔗 File imports".bright_white(),
        response.imports_edge_count.to_string().green()
    );
    println!(
        "  {:28} {:>12}",
        "📍 File→function/class".bright_white(),
        response.contains_edge_count.to_string().green()
    );
    println!(
        "  {:28} {:>12}",
        "📚 Library usage".bright_white(),
        response.uses_library_edge_count.to_string().green()
    );
    println!(
        "  {:28} {:>12}",
        "➡️  Function calls".bright_white(),
        response.calls_edge_count.to_string().green()
    );
    println!("{}", "─".repeat(45).dimmed());
    println!(
        "  {:28} {:>12}",
        "Total edges".bold(),
        response.total_edges.to_string().bold().green()
    );
    println!();

    // Insights
    if response.file_count > 0 {
        let avg_deps = response.imports_edge_count as f64 / response.file_count as f64;
        let avg_funcs = response.function_count as f64 / response.file_count as f64;

        if verbose {
            println!(
                "  {} ~{:.1} imports/file, ~{:.1} functions/file",
                "📊".dimmed(),
                avg_deps,
                avg_funcs
            );
            println!();
        }

        if avg_funcs > 10.0 {
            println!(
                "  {} Files are quite dense ({:.0} avg functions). Consider splitting.",
                "💡".yellow(),
                avg_funcs
            );
            println!();
        }
    }

    if verbose {
        println!(
            "  {} Use 'unfault graph critical' to find the most connected files.",
            "Tip:".dimmed()
        );
        println!();
    }
}

// =============================================================================
// Graph Dump Command (Local)
// =============================================================================

/// Arguments for the graph dump command
#[derive(Debug)]
pub struct DumpArgs {
    /// Workspace path to analyze (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Output only call edges
    pub calls_only: bool,
    /// Output only specific file's information
    pub file: Option<String>,
    /// Verbose output
    pub verbose: bool,
}

/// Execute the graph dump command - builds local graph and outputs JSON
pub fn execute_dump(args: DumpArgs) -> Result<i32> {
    use crate::session::graph_builder::build_local_graph;

    // Determine workspace path
    let workspace_path = match &args.workspace_path {
        Some(path) => std::path::PathBuf::from(path),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!(
            "{} Building local code graph for: {}",
            "→".cyan(),
            workspace_path.display()
        );
    }

    // Build the local graph
    let graph = build_local_graph(&workspace_path, None, args.verbose)?;

    if args.verbose {
        eprintln!(
            "{} Graph built: {} files, {} functions, {} call edges",
            "✓".green(),
            graph.files.len(),
            graph.functions.len(),
            graph.calls.len()
        );
        eprintln!();
    }

    // Filter and output
    if args.calls_only {
        // Output only call edges, optionally filtered by file
        let calls: Vec<_> = if let Some(ref file_filter) = args.file {
            graph
                .calls
                .iter()
                .filter(|c| c.caller_file.contains(file_filter))
                .collect()
        } else {
            graph.calls.iter().collect()
        };

        println!("{}", serde_json::to_string_pretty(&calls)?);
    } else if let Some(ref file_filter) = args.file {
        // Output everything related to a specific file
        #[derive(serde::Serialize)]
        struct FileGraph {
            file: Option<crate::session::graph_builder::FileNode>,
            functions: Vec<crate::session::graph_builder::FunctionNode>,
            outgoing_calls: Vec<crate::session::graph_builder::CallEdge>,
            incoming_calls: Vec<crate::session::graph_builder::CallEdge>,
            imports: Vec<crate::session::graph_builder::ImportEdge>,
        }

        let file_graph = FileGraph {
            file: graph.files.iter().find(|f| f.path.contains(file_filter)).cloned(),
            functions: graph
                .functions
                .iter()
                .filter(|f| f.file_path.contains(file_filter))
                .cloned()
                .collect(),
            outgoing_calls: graph
                .calls
                .iter()
                .filter(|c| c.caller_file.contains(file_filter))
                .cloned()
                .collect(),
            incoming_calls: graph
                .calls
                .iter()
                .filter(|c| {
                    // Find the callee's file
                    graph.functions.iter().any(|f| {
                        f.qualified_name == c.callee && f.file_path.contains(file_filter)
                    })
                })
                .cloned()
                .collect(),
            imports: graph
                .imports
                .iter()
                .filter(|i| i.from_file.contains(file_filter) || i.to_file.contains(file_filter))
                .cloned()
                .collect(),
        };

        println!("{}", serde_json::to_string_pretty(&file_graph)?);
    } else {
        // Output full graph
        println!("{}", serde_json::to_string_pretty(&graph)?);
    }

    Ok(EXIT_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impact_args_with_session_id() {
        let args = ImpactArgs {
            session_id: Some("abc123".to_string()),
            workspace_path: None,
            file_path: "main.py".to_string(),
            max_depth: 5,
            json: false,
            verbose: false,
        };
        assert_eq!(args.session_id, Some("abc123".to_string()));
        assert_eq!(args.file_path, "main.py");
        assert_eq!(args.max_depth, 5);
    }

    #[test]
    fn test_impact_args_with_workspace_path() {
        let args = ImpactArgs {
            session_id: None,
            workspace_path: Some("/path/to/project".to_string()),
            file_path: "main.py".to_string(),
            max_depth: 5,
            json: false,
            verbose: false,
        };
        assert!(args.session_id.is_none());
        assert_eq!(args.workspace_path, Some("/path/to/project".to_string()));
    }

    #[test]
    fn test_library_args() {
        let args = LibraryArgs {
            session_id: None,
            workspace_path: None,
            library_name: "requests".to_string(),
            json: false,
            verbose: false,
        };
        assert_eq!(args.library_name, "requests");
    }

    #[test]
    fn test_critical_args() {
        let args = CriticalArgs {
            session_id: Some("abc123".to_string()),
            workspace_path: None,
            limit: 10,
            sort_by: "in_degree".to_string(),
            json: true,
            verbose: false,
        };
        assert_eq!(args.limit, 10);
        assert_eq!(args.sort_by, "in_degree");
        assert!(args.json);
    }

    #[test]
    fn test_stats_args() {
        let args = StatsArgs {
            session_id: Some("abc123".to_string()),
            workspace_path: None,
            json: false,
            verbose: true,
        };
        assert_eq!(args.session_id, Some("abc123".to_string()));
        assert!(args.verbose);
    }

    #[test]
    fn test_resolve_identifier_with_session_id() {
        let result = resolve_identifier(Some("abc123"), None, false);
        assert!(result.is_ok());
        match result.unwrap() {
            ResolvedIdentifier::SessionId(sid) => assert_eq!(sid, "abc123"),
            _ => panic!("Expected SessionId"),
        }
    }
}

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
        "📊".cyan(),
        "Impact Analysis:".bold(),
        response.file_path.bright_white()
    );
    println!();

    if response.total_affected == 0 {
        println!(
            "  {} No files would be affected by changes to this file.",
            "ℹ".blue()
        );
        println!();
        return;
    }

    // Summary
    println!(
        "  {} {} file(s) would be affected by changes to this file",
        "⚠".yellow(),
        response.total_affected.to_string().bold()
    );
    println!();

    // Direct importers
    if !response.direct_importers.is_empty() {
        println!("{}", "Direct Importers".bold().underline());
        println!("{}", "─".repeat(50).dimmed());
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
    let transitive_only: Vec<_> = response
        .transitive_importers
        .iter()
        .filter(|f| f.depth.unwrap_or(1) > 1)
        .collect();

    if !transitive_only.is_empty() {
        println!("{}", "Transitive Importers".bold().underline());
        println!("{}", "─".repeat(50).dimmed());
        for file in transitive_only {
            let lang = file.language.as_deref().unwrap_or("?");
            let depth = file.depth.unwrap_or(0);
            println!(
                "  {} {} {} {}",
                "•".cyan(),
                file.path.bright_white(),
                format!("[{}]", lang).dimmed(),
                format!("(depth: {})", depth).dimmed()
            );
        }
        println!();
    }

    if verbose {
        println!(
            "  {} Direct: {}, Total: {}",
            "Stats:".dimmed(),
            response.direct_importers.len(),
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
    _verbose: bool,
) {
    println!();
    println!(
        "{} {} {}",
        "📚".cyan(),
        "Files using library:".bold(),
        library_name.bright_white()
    );
    println!();

    if let Some(files) = &response.files {
        if files.is_empty() {
            println!(
                "  {} No files use the library '{}'",
                "ℹ".blue(),
                library_name
            );
        } else {
            println!(
                "  {} Found {} file(s)",
                "✓".green(),
                files.len().to_string().bold()
            );
            println!();
            println!("{}", "Files".bold().underline());
            println!("{}", "─".repeat(50).dimmed());
            for file in files {
                let lang = file.language.as_deref().unwrap_or("?");
                println!(
                    "  {} {} {}",
                    "•".cyan(),
                    file.path.bright_white(),
                    format!("[{}]", lang).dimmed()
                );
            }
        }
    } else {
        println!("  {} No files found", "ℹ".blue());
    }
    println!();
}

fn output_deps_formatted(response: &DependencyQueryResponse, file_path: &str, verbose: bool) {
    println!();
    println!(
        "{} {} {}",
        "📦".cyan(),
        "External dependencies of:".bold(),
        file_path.bright_white()
    );
    println!();

    if let Some(deps) = &response.dependencies {
        if deps.is_empty() {
            println!("  {} No external dependencies found", "ℹ".blue());
        } else {
            println!(
                "  {} Found {} external dependencies",
                "✓".green(),
                deps.len().to_string().bold()
            );
            println!();
            println!("{}", "Dependencies".bold().underline());
            println!("{}", "─".repeat(50).dimmed());
            for dep in deps {
                let category = dep.category.as_deref().unwrap_or("Other");
                let category_colored = match category {
                    "HttpClient" => category.yellow(),
                    "Database" => category.blue(),
                    "WebFramework" => category.magenta(),
                    "AsyncRuntime" => category.cyan(),
                    "Logging" => category.green(),
                    "Resilience" => category.red(),
                    _ => category.normal(),
                };
                if verbose {
                    println!(
                        "  {} {} [{}]",
                        "•".cyan(),
                        dep.name.bright_white(),
                        category_colored
                    );
                } else {
                    println!("  {} {}", "•".cyan(), dep.name.bright_white());
                }
            }
        }
    } else {
        println!("  {} No dependencies found", "ℹ".blue());
    }
    println!();
}

fn output_critical_json(response: &CentralityResponse) -> Result<()> {
    let json = serde_json::to_string_pretty(response)?;
    println!("{}", json);
    Ok(())
}

fn output_critical_formatted(response: &CentralityResponse, verbose: bool) {
    println!();
    println!(
        "{} {} {}",
        "🎯".cyan(),
        "Most Critical Files".bold(),
        format!("(sorted by {})", response.sort_by).dimmed()
    );
    println!();

    if response.files.is_empty() {
        println!("  {} No files found in the graph", "ℹ".blue());
        println!();
        return;
    }

    println!(
        "  {} Showing top {} of {} total files",
        "ℹ".blue(),
        response.files.len(),
        response.total_files
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

        // Color-code the importance score
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
            println!(
                "      {} Total degree: {}",
                "└".dimmed(),
                file.total_degree.to_string().dimmed()
            );
        }
    }
    println!();

    // Legend
    println!(
        "  {} In: files that import this | Out: files this imports | Libs: external deps",
        "Legend:".dimmed()
    );
    println!(
        "  {} Score = In×2 + Out + Libs (higher = more critical)",
        "".dimmed()
    );
    println!();
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
            "📊".cyan(),
            "Function Impact Analysis:".bold(),
            response.function.bright_white()
        );
        println!();

        if response.total_affected == 0 {
            println!(
                "  {} No functions would be affected by changes to this function.",
                "ℹ".blue()
            );
            println!();
            return Ok(EXIT_SUCCESS);
        }

        println!(
            "  {} {} function(s) would be affected",
            "⚠".yellow(),
            response.total_affected.to_string().bold()
        );
        println!();

        // Direct callers
        if !response.direct_callers.is_empty() {
            println!("{}", "Direct Callers".bold().underline());
            println!("{}", "─".repeat(50).dimmed());
            for caller in &response.direct_callers {
                let unknown = "unknown".to_string();
                let path = caller.get("path").unwrap_or(&unknown);
                let func = caller.get("function").unwrap_or(&unknown);
                println!(
                    "  {} {} ({})",
                    "•".cyan(),
                    func.bright_white(),
                    path.dimmed()
                );
            }
            println!();
        }

        // Transitive callers
        let transitive_only: Vec<_> = response
            .transitive_callers
            .iter()
            .filter(|c| c.get("depth").and_then(|d| d.parse::<i32>().ok()) > Some(1))
            .collect();

        if !transitive_only.is_empty() {
            println!("{}", "Transitive Callers".bold().underline());
            println!("{}", "─".repeat(50).dimmed());
            for caller in transitive_only {
                let unknown = "unknown".to_string();
                let zero = "0".to_string();
                let path = caller.get("path").unwrap_or(&unknown);
                let func = caller.get("function").unwrap_or(&unknown);
                let depth = caller.get("depth").unwrap_or(&zero);
                println!(
                    "  {} {} ({}) {}",
                    "•".cyan(),
                    func.bright_white(),
                    path.dimmed(),
                    format!("(depth: {})", depth).dimmed()
                );
            }
            println!();
        }

        if args.verbose {
            println!(
                "  {} Direct: {}, Total: {}",
                "Stats:".dimmed(),
                response.direct_callers.len(),
                response.total_affected
            );
            println!();
        }
    }

    Ok(EXIT_SUCCESS)
}

fn output_stats_formatted(response: &GraphStatsResponse, _verbose: bool) {
    println!();
    println!("{} {}", "📈".cyan(), "Code Graph Statistics".bold());
    println!();

    // Nodes section
    println!("{}", "Nodes".bold().underline());
    println!("{}", "─".repeat(40).dimmed());
    println!(
        "  {:25} {:>10}",
        "Files".bright_white(),
        response.file_count.to_string().cyan()
    );
    println!(
        "  {:25} {:>10}",
        "Functions".bright_white(),
        response.function_count.to_string().cyan()
    );
    println!(
        "  {:25} {:>10}",
        "Classes".bright_white(),
        response.class_count.to_string().cyan()
    );
    println!(
        "  {:25} {:>10}",
        "External Modules".bright_white(),
        response.external_module_count.to_string().cyan()
    );
    println!("{}", "─".repeat(40).dimmed());
    println!(
        "  {:25} {:>10}",
        "Total".bold(),
        response.total_nodes.to_string().bold().cyan()
    );
    println!();

    // Edges section
    println!("{}", "Edges".bold().underline());
    println!("{}", "─".repeat(40).dimmed());
    println!(
        "  {:25} {:>10}",
        "Import relationships".bright_white(),
        response.imports_edge_count.to_string().green()
    );
    println!(
        "  {:25} {:>10}",
        "Contains (file→fn/class)".bright_white(),
        response.contains_edge_count.to_string().green()
    );
    println!(
        "  {:25} {:>10}",
        "Library usage".bright_white(),
        response.uses_library_edge_count.to_string().green()
    );
    println!(
        "  {:25} {:>10}",
        "Function calls".bright_white(),
        response.calls_edge_count.to_string().green()
    );
    println!("{}", "─".repeat(40).dimmed());
    println!(
        "  {:25} {:>10}",
        "Total".bold(),
        response.total_edges.to_string().bold().green()
    );
    println!();
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

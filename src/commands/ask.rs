//! # Ask Command
//!
//! Implements the ask command for querying project health via RAG.
//!
//! ## Usage
//!
//! ```bash
//! # Ask a question about your project
//! unfault ask "How is my service doing?"
//!
//! # Ask with a specific workspace filter
//! unfault ask "What are the main stability concerns?" --workspace wks_abc123
//!
//! # Get JSON output
//! unfault ask "Show performance issues" --json
//! ```

use anyhow::Result;
use colored::Colorize;
use std::collections::HashMap;
use std::path::Path;
use termimad::MadSkin;

use crate::api::ApiClient;
use crate::api::llm::{LlmClient, build_llm_context};
use crate::api::rag::{
    ClientGraphData, RAGDisambiguation, RAGEnumerateContext, RAGEnumerateItem, RAGFlowContext,
    RAGFlowPathNode, RAGGraphContext, RAGQueryRequest, RAGQueryResponse, RAGSloContext,
    RAGWorkspaceContext,
};
use crate::config::Config;
use crate::exit_codes::*;
use crate::session::{
    MetaFileInfo, SerializableGraph, build_local_graph, get_git_remote, get_or_compute_workspace_id,
};

/// Convert SerializableGraph to ClientGraphData for API consumption.
fn graph_to_client_data(graph: &SerializableGraph) -> ClientGraphData {
    // Convert files
    let files: Vec<HashMap<String, serde_json::Value>> = graph
        .files
        .iter()
        .map(|f| {
            let mut map = HashMap::new();
            map.insert("path".to_string(), serde_json::json!(f.path));
            map.insert("language".to_string(), serde_json::json!(f.language));
            map
        })
        .collect();

    // Convert functions with HTTP metadata
    let functions: Vec<HashMap<String, serde_json::Value>> = graph
        .functions
        .iter()
        .map(|f| {
            let mut map = HashMap::new();
            map.insert("name".to_string(), serde_json::json!(f.name));
            map.insert(
                "qualified_name".to_string(),
                serde_json::json!(f.qualified_name),
            );
            map.insert("file_path".to_string(), serde_json::json!(f.file_path));
            map.insert("is_async".to_string(), serde_json::json!(f.is_async));
            map.insert("is_handler".to_string(), serde_json::json!(f.is_handler));
            if let Some(ref method) = f.http_method {
                map.insert("http_method".to_string(), serde_json::json!(method));
            }
            if let Some(ref path) = f.http_path {
                map.insert("http_path".to_string(), serde_json::json!(path));
            }
            map
        })
        .collect();

    // Convert calls
    let calls: Vec<HashMap<String, serde_json::Value>> = graph
        .calls
        .iter()
        .map(|c| {
            let mut map = HashMap::new();
            map.insert("caller".to_string(), serde_json::json!(c.caller));
            map.insert("callee".to_string(), serde_json::json!(c.callee));
            map.insert("caller_file".to_string(), serde_json::json!(c.caller_file));
            map
        })
        .collect();

    // Convert dependency injections
    let dependency_injections: Vec<HashMap<String, serde_json::Value>> = graph
        .dependency_injections
        .iter()
        .map(|e| {
            let mut map = HashMap::new();
            map.insert("consumer".to_string(), serde_json::json!(e.consumer));
            map.insert("provider".to_string(), serde_json::json!(e.provider));
            map.insert(
                "consumer_file".to_string(),
                serde_json::json!(e.consumer_file),
            );
            map
        })
        .collect();

    // Convert imports
    let imports: Vec<HashMap<String, serde_json::Value>> = graph
        .imports
        .iter()
        .map(|i| {
            let mut map = HashMap::new();
            map.insert("from_file".to_string(), serde_json::json!(i.from_file));
            map.insert("to_file".to_string(), serde_json::json!(i.to_file));
            map.insert("items".to_string(), serde_json::json!(i.items));
            map
        })
        .collect();

    // Convert contains
    let contains: Vec<HashMap<String, serde_json::Value>> = graph
        .contains
        .iter()
        .map(|c| {
            let mut map = HashMap::new();
            map.insert("file_path".to_string(), serde_json::json!(c.file_path));
            map.insert("item_name".to_string(), serde_json::json!(c.item_name));
            map.insert("item_type".to_string(), serde_json::json!(c.item_type));
            map
        })
        .collect();

    // Convert library usage
    let library_usage: Vec<HashMap<String, serde_json::Value>> = graph
        .library_usage
        .iter()
        .map(|l| {
            let mut map = HashMap::new();
            map.insert("file_path".to_string(), serde_json::json!(l.file_path));
            map.insert("library".to_string(), serde_json::json!(l.library));
            map
        })
        .collect();

    // Convert remote servers
    let remote_servers: Vec<HashMap<String, serde_json::Value>> = graph
        .remote_servers
        .iter()
        .map(|r| {
            let mut map = HashMap::new();
            map.insert("kind".to_string(), serde_json::json!(r.kind));
            map.insert("id".to_string(), serde_json::json!(r.id));
            map.insert("display".to_string(), serde_json::json!(r.display));
            map
        })
        .collect();

    // Convert outbound HTTP calls
    let http_calls: Vec<HashMap<String, serde_json::Value>> = graph
        .http_calls
        .iter()
        .map(|e| {
            let mut map = HashMap::new();
            map.insert("caller".to_string(), serde_json::json!(e.caller));
            map.insert("caller_file".to_string(), serde_json::json!(e.caller_file));
            map.insert("remote".to_string(), serde_json::json!(e.remote));
            map.insert("method".to_string(), serde_json::json!(e.method));
            map.insert("library".to_string(), serde_json::json!(e.library));
            if let Some(ref url) = e.url {
                map.insert("url".to_string(), serde_json::json!(url));
            }
            map
        })
        .collect();

    // Convert SLOs
    let slos: Vec<HashMap<String, serde_json::Value>> = graph
        .slos
        .iter()
        .map(|s| {
            let mut map = HashMap::new();
            map.insert("id".to_string(), serde_json::json!(s.id));
            map.insert("name".to_string(), serde_json::json!(s.name));
            map.insert("provider".to_string(), serde_json::json!(s.provider));
            if let Some(ref pattern) = s.path_pattern {
                map.insert("path_pattern".to_string(), serde_json::json!(pattern));
            }
            if let Some(ref method) = s.http_method {
                map.insert("http_method".to_string(), serde_json::json!(method));
            }
            map.insert(
                "target_percent".to_string(),
                serde_json::json!(s.target_percent),
            );
            if let Some(current) = s.current_percent {
                map.insert("current_percent".to_string(), serde_json::json!(current));
            }
            if let Some(budget) = s.error_budget_remaining {
                map.insert(
                    "error_budget_remaining".to_string(),
                    serde_json::json!(budget),
                );
            }
            map.insert("timeframe".to_string(), serde_json::json!(s.timeframe));
            if let Some(ref url) = s.dashboard_url {
                map.insert("dashboard_url".to_string(), serde_json::json!(url));
            }
            map.insert(
                "monitored_routes".to_string(),
                serde_json::json!(s.monitored_routes),
            );
            map
        })
        .collect();

    // Convert stats
    let mut stats = HashMap::new();
    stats.insert("file_count".to_string(), graph.stats.file_count as i32);
    stats.insert(
        "function_count".to_string(),
        graph.stats.function_count as i32,
    );
    stats.insert("class_count".to_string(), graph.stats.class_count as i32);
    stats.insert(
        "import_edge_count".to_string(),
        graph.stats.import_edge_count as i32,
    );
    stats.insert(
        "calls_edge_count".to_string(),
        graph.stats.calls_edge_count as i32,
    );
    stats.insert(
        "remote_server_count".to_string(),
        graph.stats.remote_server_count as i32,
    );
    stats.insert(
        "http_call_edge_count".to_string(),
        graph.stats.http_call_edge_count as i32,
    );

    ClientGraphData {
        files,
        functions,
        calls,
        dependency_injections,
        imports,
        contains,
        library_usage,
        remote_servers,
        http_calls,
        slos,
        stats,
    }
}

/// Arguments for the ask command
#[derive(Debug)]
pub struct AskArgs {
    /// The natural language query
    pub query: String,
    /// Optional workspace ID to scope the query
    pub workspace_id: Option<String>,
    /// Optional workspace path to auto-detect workspace_id from
    pub workspace_path: Option<String>,
    /// Maximum sessions to retrieve
    pub max_sessions: Option<i32>,
    /// Maximum findings to retrieve
    pub max_findings: Option<i32>,
    /// Similarity threshold
    pub similarity_threshold: Option<f64>,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Generate an AI response using the configured LLM
    pub llm: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Auto-detect workspace ID from a directory.
///
/// Uses git remote, manifest files (pyproject.toml, package.json, Cargo.toml, go.mod),
/// or folder name to compute a stable workspace identifier.
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

    // Compute workspace ID (with persistent mapping)
    let result = get_or_compute_workspace_id(
        workspace_path,
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

/// Execute the ask command
///
/// Queries project health using RAG and displays the results.
///
/// # Arguments
///
/// * `args` - Command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Query completed successfully
/// * `Ok(EXIT_CONFIG_ERROR)` - Not logged in or configuration error
/// * `Ok(EXIT_AUTH_ERROR)` - API key is invalid
/// * `Ok(EXIT_NETWORK_ERROR)` - Cannot reach the API
/// * `Ok(EXIT_SERVICE_UNAVAILABLE)` - Embedding service not available
pub async fn execute(args: AskArgs) -> Result<i32> {
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

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Resolve workspace path: explicit or current directory
    let workspace_path = match args.workspace_path.as_ref() {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir().map_err(|e| {
            eprintln!(
                "{} Failed to get current directory: {}",
                "Error:".red().bold(),
                e
            );
            anyhow::anyhow!("Failed to get current directory")
        })?,
    };

    // Resolve workspace ID: use explicit ID if provided, otherwise auto-detect
    let workspace_id = if let Some(ref ws_id) = args.workspace_id {
        Some(ws_id.clone())
    } else {
        if args.verbose {
            eprintln!(
                "{} Auto-detecting workspace from: {}",
                "→".cyan(),
                workspace_path.display()
            );
        }

        detect_workspace_id(&workspace_path, args.verbose)
    };

    // Build local graph for flow analysis
    // Note: SLOs are NOT discovered here - they come from stored graph data
    // from a previous `review --discover-observability` run
    let graph_data = if args.verbose {
        eprintln!("{} Building local code graph...", "→".cyan());

        match build_local_graph(&workspace_path, None, false) {
            Ok(graph) => {
                eprintln!(
                    "  Built graph: {} files, {} functions, {} calls",
                    graph.stats.file_count,
                    graph.stats.function_count,
                    graph.stats.calls_edge_count
                );
                let client_data = graph_to_client_data(&graph);
                if client_data.slos.is_empty() {
                    eprintln!(
                        "  {} No SLOs in local graph (will use stored SLOs if available)",
                        "ℹ".dimmed()
                    );
                } else {
                    eprintln!("  {} SLOs: {}", "→".cyan(), client_data.slos.len());
                }
                Some(client_data)
            }
            Err(e) => {
                eprintln!("  {} Failed to build graph: {}", "⚠".yellow(), e);
                None
            }
        }
    } else {
        // Build silently in non-verbose mode
        build_local_graph(&workspace_path, None, false)
            .ok()
            .map(|graph| graph_to_client_data(&graph))
    };

    // Build request
    let request = RAGQueryRequest {
        query: args.query.clone(),
        workspace_id: workspace_id.clone(),
        max_sessions: args.max_sessions,
        max_findings: args.max_findings,
        similarity_threshold: args.similarity_threshold,
        graph_data,
    };

    if args.verbose {
        eprintln!("{} Querying: {}", "→".cyan(), args.query);
        if let Some(ref ws) = workspace_id {
            eprintln!("{} Workspace: {}", "→".cyan(), ws);
        }
    }

    // Execute query
    let response = match api_client.query_rag(&config.api_key, &request).await {
        Ok(response) => response,
        Err(e) => {
            if e.is_auth_error() {
                eprintln!(
                    "{} Authentication failed. Run `unfault login` to re-authenticate.",
                    "Error:".red().bold()
                );
                if args.verbose {
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
                if args.verbose {
                    eprintln!("  {}: {}", "Details".dimmed(), e);
                    eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
                }
                return Ok(EXIT_NETWORK_ERROR);
            }
            if e.is_server_error() {
                eprintln!("{} {}", "Error:".red().bold(), e);
                if args.verbose {
                    eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
                }
                return Ok(EXIT_SERVICE_UNAVAILABLE);
            }
            eprintln!("{} {}", "Error:".red().bold(), e);
            if args.verbose {
                eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
            }
            return Ok(EXIT_ERROR);
        }
    };

    // Run LLM only when explicitly requested.
    let llm_response = if args.llm {
        if !config.llm_ready() {
            eprintln!(
                "{} LLM not configured. Run `unfault config llm` to enable AI-powered answers.",
                "⚠".yellow()
            );
            eprintln!();
            None
        } else {
            let llm_config = config.llm.as_ref().unwrap();

            if args.verbose {
                eprintln!(
                    "{} Using {} ({}) for AI response...",
                    "→".cyan(),
                    llm_config.provider,
                    llm_config.model
                );
            }

            // Build rich context for LLM
            let llm_context = build_llm_context(
                &response.context_summary,
                &response.sessions,
                &response.findings,
            );

            // Create LLM client and generate response with streaming
            match LlmClient::new_with_options(llm_config, args.verbose) {
                Ok(client) => {
                    // Print header before streaming starts (include model info)
                    println!();
                    println!(
                        "{} {} {}",
                        "🤖".green(),
                        "AI Analysis".bold().underline(),
                        format!("({})", llm_config.model).dimmed()
                    );
                    println!();

                    // Stream tokens directly to stdout
                    let result = client.generate_streaming(&args.query, &llm_context).await;

                    match result {
                        Ok(text) => {
                            // Treat empty or whitespace-only responses as failures
                            let trimmed = text.trim();
                            if trimmed.is_empty() {
                                if args.verbose {
                                    eprintln!("{} LLM returned empty response", "⚠".yellow());
                                }
                                None
                            } else {
                                // Already printed via streaming, store for output logic
                                Some(trimmed.to_string())
                            }
                        }
                        Err(e) => {
                            if args.verbose {
                                eprintln!("{} LLM error: {}", "⚠".yellow(), e);
                            }
                            None
                        }
                    }
                }
                Err(e) => {
                    if args.verbose {
                        eprintln!("{} LLM client error: {}", "⚠".yellow(), e);
                    }
                    None
                }
            }
        }
    } else {
        None
    };

    // Output results
    // Note: when LLM is used with streaming, response was already printed to stdout
    let streamed = llm_response.is_some();
    if args.json {
        output_json(&response, llm_response.as_deref())?;
    } else {
        output_formatted(
            &response,
            llm_response.as_deref(),
            args.verbose,
            config.llm_ready(),
            streamed,
        );
    }

    Ok(EXIT_SUCCESS)
}

/// Output response as JSON
fn output_json(response: &RAGQueryResponse, llm_response: Option<&str>) -> Result<()> {
    // Always include the full response payload.
    let mut output = serde_json::to_value(response)?;

    if let Some(llm_text) = llm_response {
        if let Some(obj) = output.as_object_mut() {
            obj.insert("answer".to_string(), serde_json::json!(llm_text));
        }
    }

    let json = serde_json::to_string_pretty(&output)?;
    println!("{}", json);
    Ok(())
}

/// Output response as formatted text
/// Maximum width for markdown rendering
const MARKDOWN_MAX_WIDTH: usize = 80;

/// Create a styled skin for terminal markdown rendering
fn create_markdown_skin() -> MadSkin {
    let mut skin = MadSkin::default();
    // Customize colors for better terminal appearance
    skin.set_headers_fg(termimad::crossterm::style::Color::Cyan);
    skin.bold.set_fg(termimad::crossterm::style::Color::White);
    skin.italic
        .set_fg(termimad::crossterm::style::Color::Yellow);
    skin.code_block.set_fgbg(
        termimad::crossterm::style::Color::Green,
        termimad::crossterm::style::Color::Reset,
    );
    skin
}

/// Render markdown text with a maximum width
fn render_markdown(text: &str) {
    let skin = create_markdown_skin();
    // Use write_in_area which respects width, or term_text with area
    let area = termimad::Area::new(0, 0, MARKDOWN_MAX_WIDTH as u16, u16::MAX);
    let fmt_text = termimad::FmtText::from(&skin, text, Some(area.width as usize));
    print!("{}", fmt_text);
}

/// Format a flow path node for display
fn format_flow_node(node: &RAGFlowPathNode, indent: usize) -> String {
    let prefix = if indent == 0 { "" } else { "└─ " };
    let indent_str = "   ".repeat(indent);

    // Check if this function has HTTP route metadata - treat it as an API route
    let has_http_route = node.http_method.is_some() && node.http_path.is_some();

    match node.node_type.as_str() {
        "api_route" | "fastapi_route" => {
            // HTTP route node: show method and path
            let method = node.http_method.as_deref().unwrap_or("?");
            let path = node.http_path.as_deref().unwrap_or("?");
            format!(
                "{}{}Request hits {} {}",
                indent_str,
                prefix,
                method.bright_cyan().bold(),
                path.bright_white()
            )
        }
        "function" if has_http_route => {
            // Function with HTTP metadata - show as API route when at root level
            let method = node.http_method.as_deref().unwrap_or("?");
            let path = node.http_path.as_deref().unwrap_or("?");
            if indent == 0 {
                format!(
                    "{}Request hits {} {}",
                    indent_str,
                    method.bright_cyan().bold(),
                    path.bright_white()
                )
            } else {
                format!("{}{}calls {}()", indent_str, prefix, node.name.yellow())
            }
        }
        "function" => {
            // Regular function node
            // At root level (indent 0): show as "function function_name()"
            // At deeper levels: show as "calls function_name()"
            if indent == 0 {
                format!("{}function {}()", indent_str, node.name.yellow())
            } else {
                format!("{}{}calls {}()", indent_str, prefix, node.name.yellow())
            }
        }
        "external_library" => {
            // External library: show "uses library (category)"
            let category = node.category.as_deref().unwrap_or("external");
            format!(
                "{}{}uses {} ({})",
                indent_str,
                prefix,
                node.name.green().bold(),
                category.dimmed()
            )
        }
        "middleware" | "fastapi_middleware" => {
            // Middleware node
            format!(
                "{}{}Middleware {} intercepts requests",
                indent_str,
                prefix,
                node.name.magenta()
            )
        }
        _ => {
            // Generic fallback
            format!(
                "{}{}[{}] {}",
                indent_str,
                prefix,
                node.node_type.dimmed(),
                node.name
            )
        }
    }
}

/// A tree node for displaying call hierarchies
#[derive(Debug, Clone)]
struct TreeNode {
    node: RAGFlowPathNode,
    children: Vec<TreeNode>,
}

impl TreeNode {
    fn new(node: RAGFlowPathNode) -> Self {
        Self {
            node,
            children: Vec::new(),
        }
    }

    /// Recursively render the tree with proper indentation
    fn render(&self, indent: usize) -> Vec<String> {
        let mut lines = vec![format_flow_node(&self.node, indent)];
        for child in &self.children {
            lines.extend(child.render(indent + 1));
        }
        lines
    }
}

/// Build a tree structure from flat paths, respecting the depth field
/// Returns a list of root TreeNodes
fn build_trees_from_paths(paths: &[Vec<RAGFlowPathNode>]) -> Vec<TreeNode> {
    use std::collections::HashMap;

    // Group paths by root node_id
    let mut root_trees: HashMap<String, TreeNode> = HashMap::new();

    for path in paths {
        if path.is_empty() {
            continue;
        }

        let root = &path[0];
        let root_id = root.node_id.clone();

        // Get or create the root tree node
        let tree = root_trees
            .entry(root_id.clone())
            .or_insert_with(|| TreeNode::new(root.clone()));

        // Add path nodes as children, respecting depth
        // path[1] is depth 1 (child of root), path[2] is depth 2 (child of path[1]), etc.
        if path.len() > 1 {
            insert_path_into_tree(tree, &path[1..]);
        }
    }

    root_trees.into_values().collect()
}

/// Insert a path segment into a tree, creating intermediate nodes as needed
fn insert_path_into_tree(parent: &mut TreeNode, remaining_path: &[RAGFlowPathNode]) {
    if remaining_path.is_empty() {
        return;
    }

    let current = &remaining_path[0];

    // Find or create child node
    let child_idx = parent
        .children
        .iter()
        .position(|c| c.node.node_id == current.node_id);

    let child = if let Some(idx) = child_idx {
        &mut parent.children[idx]
    } else {
        parent.children.push(TreeNode::new(current.clone()));
        parent.children.last_mut().unwrap()
    };

    // Recurse for remaining path
    if remaining_path.len() > 1 {
        insert_path_into_tree(child, &remaining_path[1..]);
    }
}

/// Render flow context showing call paths
fn render_flow_context(flow_context: &RAGFlowContext, verbose: bool) {
    println!("{}", "Traversing code graph...".dimmed());
    println!(
        "{} Found {} related modules",
        "→".cyan(),
        flow_context.root_nodes.len()
    );
    println!("{} Tracing call paths from API routes...", "→".cyan());
    println!();

    if flow_context.paths.is_empty() && flow_context.root_nodes.is_empty() {
        println!("{} No call paths found", "⚠".yellow());
        return;
    }

    // Determine topic from root nodes or query
    // Prefer the first root node's name, capitalize it properly
    let topic = if let Some(first_root) = flow_context.root_nodes.first() {
        // Extract just the function/class name and capitalize
        let name = &first_root.name;
        // For names like "get_user", extract "user" and capitalize
        let topic = if name.starts_with("get_") || name.starts_with("set_") {
            &name[4..]
        } else if let Some(prefix) = ["handle_", "create_", "delete_", "update_"]
            .iter()
            .find(|p| name.starts_with(**p))
        {
            &name[prefix.len()..]
        } else {
            name.as_str()
        };
        // Capitalize first letter
        let mut chars = topic.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().to_string() + chars.as_str(),
            None => "Flow".to_string(),
        }
    } else if let Some(q) = &flow_context.query {
        // Fallback: capitalize the query target
        let mut chars = q.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().to_string() + chars.as_str(),
            None => "Flow".to_string(),
        }
    } else {
        "Flow".to_string()
    };

    println!("{} flow identified:", topic.bright_white().bold());
    println!();

    // Build tree structure from paths
    let trees = build_trees_from_paths(&flow_context.paths);

    // Track unique nodes and edges for stats
    let mut total_nodes = 0;
    let mut total_edges = 0;

    // Count nodes recursively
    fn count_tree(tree: &TreeNode, nodes: &mut usize, edges: &mut usize) {
        *nodes += 1;
        for child in &tree.children {
            *edges += 1;
            count_tree(child, nodes, edges);
        }
    }

    // Render each tree
    for (i, tree) in trees.iter().enumerate() {
        count_tree(tree, &mut total_nodes, &mut total_edges);
        let lines = tree.render(0);
        for (j, line) in lines.iter().enumerate() {
            if j == 0 {
                println!("{}. {}", i + 1, line);
            } else {
                println!("   {}", line);
            }
        }

        if i < trees.len() - 1 {
            println!();
        }
    }

    println!();
    println!(
        "Graph context: {} nodes, {} edges traversed",
        total_nodes.to_string().cyan(),
        total_edges.to_string().cyan()
    );

    if verbose {
        println!();
        println!("{}", "─".repeat(50).dimmed());
        println!(
            "{} {} root node(s), {} call path(s)",
            "📊".cyan(),
            flow_context.root_nodes.len(),
            flow_context.paths.len()
        );
    }
}

fn graph_context_has_data(ctx: &RAGGraphContext) -> bool {
    !ctx.affected_files.is_empty() || !ctx.library_users.is_empty() || !ctx.dependencies.is_empty()
}

fn render_graph_context(ctx: &RAGGraphContext, verbose: bool) {
    let title = match ctx.query_type.as_str() {
        "impact" => "Impact analysis",
        "library" => "Usage",
        "dependencies" => "External dependencies",
        "centrality" => {
            // Check if this is function or file centrality
            if ctx.centrality_target.as_deref() == Some("function") {
                "Most called functions"
            } else {
                "Most connected files"
            }
        }
        other => other,
    };

    println!("{}", title.bold());

    if ctx.query_type == "impact" {
        let target = ctx.target_file.as_deref().unwrap_or("target");

        let mut callers = Vec::new();
        let mut dependency_consumers = Vec::new();
        for rel in &ctx.affected_files {
            let rel_kind = rel.relationship.as_deref().unwrap_or("calls");
            if rel_kind.contains("dependency") {
                dependency_consumers.push(rel);
            } else {
                callers.push(rel);
            }
        }

        if callers.is_empty() && dependency_consumers.is_empty() {
            println!(
                "  {} No callers found for {} (may still be invoked indirectly)",
                "ℹ".blue(),
                target.cyan()
            );
        } else {
            if callers.is_empty() && !dependency_consumers.is_empty() {
                println!(
                    "  {} No callers found, but used as a dependency by:",
                    "→".cyan()
                );
            } else if !callers.is_empty() {
                println!("  {} Called by:", "→".cyan());
            }

            for (idx, rel) in callers.iter().enumerate() {
                render_impact_relation(idx, rel, verbose);
            }

            if !dependency_consumers.is_empty() {
                if !callers.is_empty() {
                    println!();
                    println!("  {} Used as a dependency by:", "→".cyan());
                }

                for (idx, rel) in dependency_consumers.iter().enumerate() {
                    render_impact_relation(idx, rel, verbose);
                }
            }
        }
    }

    if ctx.query_type == "library" && !ctx.library_users.is_empty() {
        println!();
        println!("  {} Files using it:", "→".cyan());
        for (idx, rel) in ctx.library_users.iter().enumerate() {
            let path = rel.path.as_deref().unwrap_or("<unknown>");
            let relationship = rel.relationship.as_deref().unwrap_or("uses");
            // Only show relationship detail if we have usage info
            let relation_display = match rel.usage.as_deref() {
                Some(usage) if !usage.is_empty() => format!("({} {})", relationship, usage),
                _ => format!("({})", relationship),
            };
            println!(
                "  {} {} {}",
                format!("{}.", idx + 1).bright_white(),
                path.cyan(),
                relation_display.dimmed()
            );
        }
    }

    if ctx.query_type == "dependencies" && !ctx.dependencies.is_empty() {
        println!();
        println!("  {} External dependencies:", "→".cyan());
        for dep in &ctx.dependencies {
            let name = dep.name.as_deref().unwrap_or("dependency");
            let category = dep.category.as_deref().unwrap_or("library");
            println!("  • {} ({})", name.green(), category.dimmed());
        }
    }

    if ctx.query_type == "centrality" && !ctx.affected_files.is_empty() {
        let is_function_centrality = ctx.centrality_target.as_deref() == Some("function");

        println!();
        if is_function_centrality {
            println!(
                "  {} These functions are called by the most other functions:",
                "→".cyan()
            );
        } else {
            println!(
                "  {} These files have the most imports/calls — changes here ripple the furthest:",
                "→".cyan()
            );
        }

        for (idx, rel) in ctx.affected_files.iter().enumerate() {
            if is_function_centrality {
                // Function centrality display
                let name = rel
                    .name
                    .as_deref()
                    .or(rel.qualified_name.as_deref())
                    .unwrap_or("<unknown>");
                let file_path = rel.path.as_deref().unwrap_or("");
                let in_degree = rel.in_degree.unwrap_or(0);

                // Show route info if this is a route handler
                let route_info = if rel.is_route == Some(true) {
                    let method = rel.http_method.as_deref().unwrap_or("?");
                    let path = rel.http_path.as_deref().unwrap_or("?");
                    format!(" {} {}", method.green(), path)
                } else {
                    String::new()
                };

                if verbose {
                    println!(
                        "  {} {}{} ({}, {} callers)",
                        format!("{}.", idx + 1).bright_white(),
                        name.cyan(),
                        route_info,
                        file_path.dimmed(),
                        in_degree
                    );
                } else {
                    println!(
                        "  {} {}{} ({} callers)",
                        format!("{}.", idx + 1).bright_white(),
                        name.cyan(),
                        route_info,
                        in_degree
                    );
                }
            } else {
                // File centrality display
                let path = rel.path.as_deref().unwrap_or("<unknown>");
                let in_degree = rel.in_degree.unwrap_or(0);

                if verbose {
                    println!(
                        "  {} {} ({} importers)",
                        format!("{}.", idx + 1).bright_white(),
                        path.cyan(),
                        in_degree
                    );
                } else {
                    println!(
                        "  {} {}",
                        format!("{}.", idx + 1).bright_white(),
                        path.cyan()
                    );
                }
            }
        }
    }

    if verbose {
        println!();
        println!(
            "{} target: {}",
            "Target".dimmed(),
            ctx.target_file.as_deref().unwrap_or("n/a").dimmed()
        );
    }
}

fn render_impact_relation(idx: usize, rel: &crate::api::rag::RAGGraphFileRelation, verbose: bool) {
    let path = rel.path.as_deref().unwrap_or("<unknown>");
    let function = rel
        .function
        .as_deref()
        .map(|f| format!(" :: {}", f.yellow()))
        .unwrap_or_default();
    let depth = rel.depth.unwrap_or(0);
    let hops = if depth == 1 { "hop" } else { "hops" };

    println!(
        "  {} {}{} ({} {} away)",
        format!("{}.", idx + 1).bright_white(),
        path.cyan(),
        function,
        depth,
        hops
    );

    if verbose {
        if let Some(session) = rel.session_id.as_deref() {
            println!("     {} Session: {}", "".dimmed(), session);
        }
    }
}

/// Render SLO context showing SLO status and route monitoring coverage.
fn render_slo_context(slo_context: &RAGSloContext, verbose: bool) {
    println!("{} {}", "📊".cyan(), "SLO Status".bold());

    // Summary line
    let slo_count = slo_context.slos.len();
    let monitored_count = slo_context.monitored_routes.len();
    let unmonitored_count = slo_context.unmonitored_routes.len();
    let total_routes = monitored_count + unmonitored_count;

    if total_routes > 0 {
        let coverage = (monitored_count as f64 / total_routes as f64 * 100.0).round() as i32;
        println!(
            "  {} {}/{} routes monitored ({}% coverage)",
            "→".cyan(),
            monitored_count.to_string().green(),
            total_routes,
            coverage
        );
    }

    println!();

    // List SLOs
    println!("  {} SLOs ({}):", "→".cyan(), slo_count);
    for slo in &slo_context.slos {
        let target = slo
            .target_percent
            .map(|t| format!("{:.1}%", t))
            .unwrap_or_else(|| "n/a".to_string());

        let status = if let Some(budget) = slo.error_budget_remaining {
            if budget < 10.0 {
                format!("{:.1}% budget", budget).red().to_string()
            } else if budget < 30.0 {
                format!("{:.1}% budget", budget).yellow().to_string()
            } else {
                format!("{:.1}% budget", budget).green().to_string()
            }
        } else {
            "budget n/a".dimmed().to_string()
        };

        println!(
            "    {} {} [target: {}, {}]",
            "•".cyan(),
            slo.name.bright_white(),
            target,
            status
        );

        if verbose {
            if let Some(ref url) = slo.dashboard_url {
                println!("      {} {}", "Dashboard:".dimmed(), url.dimmed());
            }
            if let Some(ref pattern) = slo.path_pattern {
                println!("      {} {}", "Pattern:".dimmed(), pattern.dimmed());
            }
        }
    }

    // Show unmonitored routes if any (in verbose mode or if there are few)
    if !slo_context.unmonitored_routes.is_empty() {
        let show_unmonitored = verbose || slo_context.unmonitored_routes.len() <= 5;

        if show_unmonitored {
            println!();
            println!(
                "  {} Unmonitored routes ({}):",
                "⚠".yellow(),
                slo_context.unmonitored_routes.len()
            );
            for route in slo_context.unmonitored_routes.iter().take(10) {
                let method = route.http_method.as_deref().unwrap_or("?");
                let path = route.http_path.as_deref().unwrap_or("?");
                let file = route.file_path.as_deref().unwrap_or("");
                println!(
                    "    {} {} {} ({})",
                    "•".dimmed(),
                    method.yellow(),
                    path,
                    file.dimmed()
                );
            }
            if slo_context.unmonitored_routes.len() > 10 {
                println!(
                    "    {} ... and {} more",
                    "".dimmed(),
                    slo_context.unmonitored_routes.len() - 10
                );
            }
        } else {
            println!();
            println!(
                "  {} {} unmonitored routes (use --verbose to see them)",
                "⚠".yellow(),
                slo_context.unmonitored_routes.len()
            );
        }
    }
}

/// Render enumerate context showing counts and listings of code elements.
fn render_enumerate_context(enumerate_context: &RAGEnumerateContext, verbose: bool) {
    use colored::Colorize;

    // Header with count
    println!("{} {}", "📋".cyan(), enumerate_context.summary.bold());

    if enumerate_context.items.is_empty() {
        return;
    }

    println!();

    // Group items by file for better organization
    let mut items_by_file: std::collections::HashMap<String, Vec<&RAGEnumerateItem>> =
        std::collections::HashMap::new();
    for item in &enumerate_context.items {
        let file = item.file_path.as_deref().unwrap_or("(unknown)").to_string();
        items_by_file.entry(file).or_default().push(item);
    }

    // Determine how many items to show
    let max_items = if verbose { 50 } else { 10 };
    let mut shown = 0;

    for (file, items) in items_by_file.iter() {
        if shown >= max_items {
            break;
        }

        println!("  {} {}", "→".cyan(), file.dimmed());

        for item in items.iter() {
            if shown >= max_items {
                break;
            }

            match item.item_type.as_str() {
                "route" => {
                    let method = item.http_method.as_deref().unwrap_or("?");
                    let path = item.http_path.as_deref().unwrap_or("?");

                    // Color the HTTP method
                    let method_colored = match method.to_uppercase().as_str() {
                        "GET" => method.green(),
                        "POST" => method.blue(),
                        "PUT" | "PATCH" => method.yellow(),
                        "DELETE" => method.red(),
                        _ => method.normal(),
                    };

                    println!(
                        "    {} {} {}",
                        "•".dimmed(),
                        method_colored,
                        path.bright_white()
                    );

                    if verbose {
                        if let Some(ref name) = item.qualified_name {
                            println!("      {} {}", "fn:".dimmed(), name.dimmed());
                        }
                    }
                }
                "function" => {
                    let name = item.qualified_name.as_deref().unwrap_or(&item.name);
                    println!("    {} {}", "•".dimmed(), name.bright_white());
                }
                "file" => {
                    // Files are already shown as headers, skip individual items
                }
                "class" => {
                    println!("    {} class {}", "•".dimmed(), item.name.bright_white());
                }
                _ => {
                    println!("    {} {}", "•".dimmed(), item.name);
                }
            }

            shown += 1;
        }
    }

    if enumerate_context.truncated || shown < enumerate_context.count as usize {
        println!();
        println!(
            "  {} Showing {} of {} total{}",
            "…".dimmed(),
            shown,
            enumerate_context.count,
            if !verbose {
                " (use --verbose for more)"
            } else {
                ""
            }
        );
    }
}

const MAX_ASK_WIDTH: usize = 80;

fn wrap_paragraph(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let extra = if current.is_empty() { 0 } else { 1 };
        if current.len() + word.len() + extra > width {
            if !current.is_empty() {
                lines.push(current);
                current = String::new();
            }
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn color_paths(line: &str) -> String {
    // Match the review summary: paths stand out in bold purple.
    let scope_rgb = (210u8, 168u8, 255u8);

    let mut out = line.to_string();
    for token in line.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| c == ',' || c == '.' || c == ')' || c == ';');
        let is_path_like = cleaned.contains('/')
            || cleaned.ends_with(".go")
            || cleaned.ends_with(".py")
            || cleaned.ends_with(".rs")
            || cleaned.ends_with(".ts")
            || cleaned.ends_with(".tsx");

        if is_path_like {
            out = out.replace(
                cleaned,
                &cleaned
                    .truecolor(scope_rgb.0, scope_rgb.1, scope_rgb.2)
                    .bold()
                    .to_string(),
            );
        }
    }
    out
}

/// Convert a rule_id to a human-readable description.
/// e.g., "python.http.missing_timeout" -> "HTTP calls missing timeout"
fn describe_rule_id(rule_id: &str) -> String {
    // Common rule patterns and their descriptions
    let descriptions: &[(&str, &str)] = &[
        ("missing_timeout", "HTTP calls missing timeout"),
        ("missing_error_handling", "missing error handling"),
        ("unhandled_exception", "unhandled exceptions"),
        ("sql_injection", "potential SQL injection"),
        ("hardcoded_secret", "hardcoded secrets"),
        ("missing_auth", "missing authentication"),
        ("n_plus_one", "N+1 query patterns"),
        ("missing_index", "missing database indexes"),
        ("unbounded_query", "unbounded queries"),
        ("missing_logging", "missing logging"),
        ("missing_tracing", "missing tracing"),
        ("deprecated_api", "deprecated API usage"),
        ("race_condition", "potential race conditions"),
        ("memory_leak", "potential memory leaks"),
        ("blocking_call", "blocking calls in async context"),
    ];

    // Check for known patterns
    let rule_lower = rule_id.to_lowercase();
    for (pattern, desc) in descriptions {
        if rule_lower.contains(pattern) {
            return desc.to_string();
        }
    }

    // Fallback: clean up the rule_id itself
    // "python.http.missing_timeout" -> "missing timeout"
    let parts: Vec<&str> = rule_id.split('.').collect();
    if let Some(last) = parts.last() {
        // Convert snake_case to spaces
        return last.replace('_', " ");
    }

    rule_id.to_string()
}

fn pick_variant<'a>(seed: &str, variants: &'a [&'a str]) -> &'a str {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    let idx = (hasher.finish() as usize) % variants.len().max(1);
    variants[idx]
}

fn quick_take_seed(response: &RAGQueryResponse) -> String {
    let source = response
        .sources
        .first()
        .map(|s| s.id.as_str())
        .unwrap_or("no_source");

    format!(
        "{}:{}:{}",
        response.query,
        response.topic_label.as_deref().unwrap_or("no_topic"),
        source
    )
}

fn is_broad_health_query(query: &str) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return false;
    }
    // Broad, "how is it doing" style queries where a brief should be preferred.
    q.contains("how is")
        || q.contains("how's")
        || q.contains("doing")
        || q.contains("health")
        || q.contains("status")
        || q.contains("production")
        || q.contains("prod")
        || q.contains("reliab")
        || q.contains("operab")
        || q.contains("readiness")
        || q.contains("are we ok")
        || q.contains("is this service")
        || q.contains("project health")
}

fn is_workspace_overview_query(query: &str) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return false;
    }

    if matches!(
        q.as_str(),
        "describe this workspace"
            | "describe the workspace"
            | "describe this repo"
            | "describe this repository"
            | "describe this codebase"
            | "workspace overview"
            | "project overview"
            | "repo overview"
            | "codebase overview"
    ) {
        return true;
    }

    // Loose match (keep conservative to avoid false positives).
    (q.contains("describe") || q.contains("overview") || q.contains("summar"))
        && (q.contains("workspace")
            || q.contains("repo")
            || q.contains("repository")
            || q.contains("codebase")
            || q.contains("project"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderIntent {
    Overview,
    Operability,
    Flow,
    Impact,
    Dependencies,
    Enumerate,
    Observability,
    Findings,
    Sessions,
    Unknown,
}

fn workspace_one_liner(
    ctx: &RAGWorkspaceContext,
    graph_stats: Option<&std::collections::HashMap<String, i32>>,
) -> String {
    let kind = ctx.kind.as_deref().unwrap_or("workspace");

    let mut langs: Vec<(&String, &i32)> = ctx.languages.iter().collect();
    langs.sort_by(|a, b| b.1.cmp(a.1));
    let primary_lang = langs.first().map(|(l, _)| l.as_str()).unwrap_or("unknown");

    let fw = if ctx.frameworks.is_empty() {
        "".to_string()
    } else {
        format!(" ({})", ctx.frameworks.join(", "))
    };

    let scale = graph_stats.map(|stats| {
        let file_count = stats.get("file_count").copied().unwrap_or(0);
        let fn_count = stats.get("function_count").copied().unwrap_or(0);
        let route_count = stats.get("route_count").copied().unwrap_or(0);
        if file_count == 0 && fn_count == 0 && route_count == 0 {
            "".to_string()
        } else {
            format!(" Scale: {file_count} files, {fn_count} functions, {route_count} routes.")
        }
    });

    let start = ctx
        .entrypoints
        .first()
        .or_else(|| ctx.central_files.first().map(|f| &f.path));

    let mut s = format!("This looks like a {primary_lang} {kind}{fw}.");
    if let Some(scale) = scale {
        if !scale.is_empty() {
            s.push_str(&scale);
        }
    }
    if let Some(p) = start {
        s.push_str(&format!(" If you want a starting point, begin at {}.", p));
    }

    s
}

fn render_workspace_brief(
    ctx: &RAGWorkspaceContext,
    graph_stats: Option<&std::collections::HashMap<String, i32>>,
) {
    println!("{}", "At a glance".bold());

    // Keep the brief compact (supporting evidence for the one-liner).
    if !ctx.entrypoints.is_empty() {
        println!(
            "  {} {}",
            "Entrypoints:".dimmed(),
            ctx.entrypoints
                .iter()
                .take(4)
                .map(|p| color_paths(p))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !ctx.central_files.is_empty() {
        println!(
            "  {} {}",
            "Hotspots:".dimmed(),
            ctx.central_files
                .iter()
                .take(4)
                .map(|f| color_paths(&f.path))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !ctx.top_dependencies.is_empty() {
        println!(
            "  {} {}",
            "Dependencies:".dimmed(),
            ctx.top_dependencies
                .iter()
                .take(8)
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !ctx.depends_on.is_empty() {
        let s = ctx
            .depends_on
            .iter()
            .take(5)
            .map(|w| {
                let name = w.package_name.as_deref().unwrap_or(w.workspace_id.as_str());
                format!("{} ({})", name, w.edge_count)
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Depends on:".dimmed(), s);
    }

    if !ctx.depended_on_by.is_empty() {
        let s = ctx
            .depended_on_by
            .iter()
            .take(5)
            .map(|w| {
                let name = w.package_name.as_deref().unwrap_or(w.workspace_id.as_str());
                format!("{} ({})", name, w.edge_count)
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Depended by:".dimmed(), s);
    }

    if !ctx.remote_servers.is_empty() {
        println!(
            "  {} {}",
            "Outbound:".dimmed(),
            ctx.remote_servers
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if let Some(stats) = graph_stats {
        let file_count = stats.get("file_count").copied().unwrap_or(0);
        let fn_count = stats.get("function_count").copied().unwrap_or(0);
        let route_count = stats.get("route_count").copied().unwrap_or(0);
        if file_count > 0 || fn_count > 0 || route_count > 0 {
            println!(
                "  {} {} files, {} functions, {} routes",
                "Scale:".dimmed(),
                file_count,
                fn_count,
                route_count
            );
        }
    }
}

fn classify_render_intent(response: &RAGQueryResponse, llm_response: Option<&str>) -> RenderIntent {
    if llm_response.is_some() {
        return RenderIntent::Unknown;
    }

    let q = response.query.as_str();

    let has_flow_context = response
        .flow_context
        .as_ref()
        .is_some_and(|fc| !fc.paths.is_empty() || !fc.root_nodes.is_empty());
    if has_flow_context {
        return RenderIntent::Flow;
    }

    if let Some(gc) = &response.graph_context {
        if graph_context_has_data(gc) {
            match gc.query_type.as_str() {
                "impact" => return RenderIntent::Impact,
                "dependencies" | "library" => return RenderIntent::Dependencies,
                "centrality" => return RenderIntent::Overview,
                _ => {}
            }
        }
    }

    if response.enumerate_context.is_some() {
        return RenderIntent::Enumerate;
    }

    if response
        .slo_context
        .as_ref()
        .is_some_and(|sc| !sc.slos.is_empty())
    {
        return RenderIntent::Observability;
    }

    // Broad intent routing based on the user query.
    // These should win over generic findings/session summaries.
    if is_workspace_overview_query(q) {
        return RenderIntent::Overview;
    }
    if is_broad_health_query(q) {
        return RenderIntent::Operability;
    }

    if !response.findings.is_empty() {
        return RenderIntent::Findings;
    }
    if !response.sessions.is_empty() {
        return RenderIntent::Sessions;
    }

    RenderIntent::Unknown
}

fn should_show_health_section(response: &RAGQueryResponse, llm_response: Option<&str>) -> bool {
    matches!(
        classify_render_intent(response, llm_response),
        RenderIntent::Operability
    ) && (!response.findings.is_empty()
        || !response.sessions.is_empty()
        || response
            .slo_context
            .as_ref()
            .is_some_and(|sc| !sc.slos.is_empty()))
}

fn should_show_worth_a_look(
    response: &RAGQueryResponse,
    llm_response: Option<&str>,
    verbose: bool,
) -> bool {
    if verbose {
        return false;
    }
    if response.findings.is_empty() {
        return false;
    }

    matches!(
        classify_render_intent(response, llm_response),
        RenderIntent::Findings
    )
}

fn render_health_section(response: &RAGQueryResponse) {
    use std::collections::HashMap;

    let mut rule_counts: HashMap<String, i32> = HashMap::new();
    let mut file_counts: HashMap<String, i32> = HashMap::new();
    let mut dim_counts: HashMap<String, i32> = HashMap::new();

    for f in &response.findings {
        if let Some(rule_id) = &f.rule_id {
            *rule_counts.entry(rule_id.clone()).or_insert(0) += 1;
        }
        if let Some(path) = &f.file_path {
            *file_counts.entry(path.clone()).or_insert(0) += 1;
        }
        if let Some(dim) = &f.dimension {
            *dim_counts.entry(dim.clone()).or_insert(0) += 1;
        }
    }

    // Fall back to session dimensions if findings lack them.
    if dim_counts.is_empty() {
        for s in &response.sessions {
            for (dim, count) in &s.dimension_counts {
                *dim_counts.entry(dim.clone()).or_insert(0) += *count;
            }
        }
    }

    println!("{}", "Worth checking".bold());

    if !dim_counts.is_empty() {
        let mut dims: Vec<(&String, &i32)> = dim_counts.iter().collect();
        dims.sort_by(|a, b| b.1.cmp(a.1));
        let s = dims
            .into_iter()
            .take(3)
            .map(|(d, c)| format!("{} ({})", d, c))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Themes:".dimmed(), s);
    }

    if !rule_counts.is_empty() {
        let mut rules: Vec<(&String, &i32)> = rule_counts.iter().collect();
        rules.sort_by(|a, b| b.1.cmp(a.1));
        let s = rules
            .into_iter()
            .take(4)
            .map(|(r, c)| format!("{} ({})", describe_rule_id(r), c))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Gaps:".dimmed(), s);
    }

    if !file_counts.is_empty() {
        let mut files: Vec<(&String, &i32)> = file_counts.iter().collect();
        files.sort_by(|a, b| b.1.cmp(a.1));
        let s = files
            .into_iter()
            .take(4)
            .map(|(p, c)| format!("{} ({})", color_paths(p), c))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Hotspots:".dimmed(), s);
    }

    if let Some(slo_context) = &response.slo_context {
        if !slo_context.slos.is_empty() {
            let total_routes =
                slo_context.monitored_routes.len() + slo_context.unmonitored_routes.len();
            if total_routes > 0 {
                let coverage = (slo_context.monitored_routes.len() as f64 / total_routes as f64
                    * 100.0)
                    .round() as i32;
                println!(
                    "  {} {}/{} routes monitored ({}% coverage)",
                    "SLOs:".dimmed(),
                    slo_context.monitored_routes.len(),
                    total_routes,
                    coverage
                );
            }
        }
    }
}

/// Highlight unfault commands within a hint string.
///
/// Finds patterns like 'unfault review --discover-observability' and highlights them.
fn highlight_unfault_commands(hint: &str) -> String {
    use regex::Regex;

    // Match 'unfault <command> [--flags...]' patterns
    let re = Regex::new(r"'(unfault\s+[^']+)'").unwrap();

    re.replace_all(hint, |caps: &regex::Captures| {
        format!("'{}'", caps[1].bright_yellow())
    })
    .to_string()
}

fn build_colleague_reply(response: &RAGQueryResponse) -> String {
    let seed = quick_take_seed(response);

    if let Some(hint) = &response.hint {
        // If hint indicates "no results found" or "all clear" style message, don't add a confusing prefix
        let is_standalone_hint = hint.contains("couldn't find")
            || hint.contains("don't have any context")
            || hint.contains("no graph data")
            || hint.contains("no SLO data")
            || hint.contains("possible targets")
            || hint.contains("issues found")  // "No X issues found in your codebase"
            || hint.contains("looks clean"); // "Your code looks clean"

        let styled_hint = highlight_unfault_commands(hint);

        if is_standalone_hint {
            // Just return the hint as-is for "no results" or "all clear" messages
            return styled_hint;
        }

        // For clarification-seeking hints, add a friendly prefix
        let prefix = pick_variant(
            &seed,
            &[
                "Alright — I can help, but I need one small detail.",
                "Makes sense. I can do that, I just need a concrete target.",
                "Happy to help. Quick clarification first:",
            ],
        );
        return format!("{} {}", prefix, styled_hint);
    }

    match classify_render_intent(response, None) {
        RenderIntent::Overview | RenderIntent::Operability => {
            if let Some(ctx) = &response.workspace_context {
                return workspace_one_liner(ctx, response.graph_stats.as_ref());
            }
        }
        _ => {}
    }

    // Handle enumerate context (how many routes, list functions, etc.)
    if let Some(enumerate_context) = &response.enumerate_context {
        let opener = pick_variant(
            &seed,
            &[
                "Here's what I found:",
                "Got it. Here's the breakdown:",
                "Alright, here's the count:",
            ],
        );
        return format!("{} {}", opener, enumerate_context.summary);
    }

    // Handle SLO/Observability context
    if let Some(slo_context) = &response.slo_context {
        if !slo_context.slos.is_empty() {
            let slo_count = slo_context.slos.len();
            let monitored_count = slo_context.monitored_routes.len();
            let unmonitored_count = slo_context.unmonitored_routes.len();
            let total_routes = monitored_count + unmonitored_count;

            let opener = pick_variant(
                &seed,
                &[
                    "Here's what I found on SLOs:",
                    "I found some SLO data:",
                    "Here's the observability picture:",
                ],
            );

            let mut summary = format!("{} You have {} SLO(s) configured.", opener, slo_count);

            if total_routes > 0 {
                let coverage =
                    (monitored_count as f64 / total_routes as f64 * 100.0).round() as i32;
                summary.push_str(&format!(
                    " {}/{} routes are monitored ({}% coverage).",
                    monitored_count, total_routes, coverage
                ));
            }

            // List SLO names
            let slo_names: Vec<&str> = slo_context
                .slos
                .iter()
                .take(3)
                .map(|s| s.name.as_str())
                .collect();
            if !slo_names.is_empty() {
                summary.push_str(&format!(" SLOs: {}.", slo_names.join(", ")));
            }

            return summary;
        }
    }

    if let Some(flow_context) = &response.flow_context {
        let has_flow = !flow_context.paths.is_empty() || !flow_context.root_nodes.is_empty();
        if has_flow {
            let opener = pick_variant(
                &seed,
                &[
                    "Alright. Here’s the shape of the flow I’m seeing:",
                    "From what I can see, the flow generally goes:",
                    "Here’s the rough call path:",
                ],
            );

            if let Some(path) = flow_context.paths.first() {
                if let (Some(first), Some(last)) = (path.first(), path.last()) {
                    let start = first
                        .path
                        .as_ref()
                        .map(|p| format!("{} ({})", first.name, p))
                        .unwrap_or_else(|| first.name.clone());
                    let end = last
                        .path
                        .as_ref()
                        .map(|p| format!("{} ({})", last.name, p))
                        .unwrap_or_else(|| last.name.clone());

                    if path.len() <= 2 {
                        return format!("{} {} → {}.", opener, start, end);
                    }

                    let mid = &path[1];
                    let mid_s = mid
                        .path
                        .as_ref()
                        .map(|p| format!("{} ({})", mid.name, p))
                        .unwrap_or_else(|| mid.name.clone());

                    return format!("{} {} → {} → {}.", opener, start, mid_s, end);
                }
            }

            if let Some(root) = flow_context.root_nodes.first() {
                let start = root
                    .path
                    .as_ref()
                    .map(|p| format!("{} ({})", root.name, p))
                    .unwrap_or_else(|| root.name.clone());

                let prefix = pick_variant(
                    &seed,
                    &[
                        "If you want a good starting point, I’d begin at",
                        "A calm starting point is",
                        "I’d start by reading",
                    ],
                );

                return format!("{} {}.", prefix, start);
            }
        }
    }

    if let Some(graph_context) = &response.graph_context {
        let target = graph_context
            .target_file
            .as_deref()
            .unwrap_or("your target");

        // Impact: even an empty result is meaningful.
        if graph_context.query_type == "impact" {
            let mut callers = Vec::new();
            let mut dependency_consumers = Vec::new();
            for rel in &graph_context.affected_files {
                let rel_kind = rel.relationship.as_deref().unwrap_or("calls");
                if rel_kind.contains("dependency") {
                    dependency_consumers.push(rel);
                } else {
                    callers.push(rel);
                }
            }

            if callers.is_empty() && dependency_consumers.is_empty() {
                return format!(
                    "I don’t see any internal callers for {} in the call graph. That can mean it’s unused, or it’s invoked indirectly (FastAPI dependencies, background tasks, reflection). I’d still grep for references and run the tests.",
                    target
                );
            }

            if callers.is_empty() && !dependency_consumers.is_empty() {
                let top: Vec<&str> = dependency_consumers
                    .iter()
                    .filter_map(|r| r.path.as_deref())
                    .take(3)
                    .collect();

                let suffix = if top.is_empty() {
                    "".to_string()
                } else {
                    format!(" Top: {}.", top.join(", "))
                };

                return format!(
                    "No callers found for {}, but it’s used as a dependency by {} function(s).{}",
                    target,
                    dependency_consumers.len(),
                    suffix
                );
            }

            let n = graph_context.affected_files.len();
            let top: Vec<&str> = graph_context
                .affected_files
                .iter()
                .filter_map(|r| r.path.as_deref())
                .take(3)
                .collect();

            let suffix = if top.is_empty() {
                "".to_string()
            } else {
                format!(" Top: {}.", top.join(", "))
            };

            let extra = if dependency_consumers.is_empty() {
                "".to_string()
            } else {
                format!(
                    " (plus {} dependency consumer(s))",
                    dependency_consumers.len()
                )
            };

            return format!(
                "If you change {}, I’m seeing {} downstream usage site(s){}.{}",
                target, n, extra, suffix
            );
        }

        if graph_context_has_data(graph_context) {
            if graph_context.query_type == "dependencies" && !graph_context.dependencies.is_empty()
            {
                let n = graph_context.dependencies.len();
                let top: Vec<&str> = graph_context
                    .dependencies
                    .iter()
                    .filter_map(|d| d.name.as_deref())
                    .take(4)
                    .collect();

                let list = if top.is_empty() {
                    "".to_string()
                } else {
                    format!(" A few that stand out: {}.", top.join(", "))
                };

                return format!(
                    "{} pulls in {} external dependency/dependencies.{}",
                    target, n, list
                );
            }

            if graph_context.query_type == "library" && !graph_context.library_users.is_empty() {
                let n = graph_context.library_users.len();
                let site_word = if n == 1 { "site" } else { "sites" };
                return format!(
                    "Found {} usage {} for {}.",
                    n,
                    site_word,
                    target.bright_yellow().bold()
                );
            }

            if graph_context.query_type == "centrality" && !graph_context.affected_files.is_empty()
            {
                let is_function_centrality =
                    graph_context.centrality_target.as_deref() == Some("function");

                if is_function_centrality {
                    // Function centrality: show function names
                    let top: Vec<String> = graph_context
                        .affected_files
                        .iter()
                        .take(5)
                        .map(|r| {
                            r.name
                                .as_deref()
                                .or(r.qualified_name.as_deref())
                                .unwrap_or("<unknown>")
                                .to_string()
                        })
                        .collect();

                    let list = if top.is_empty() {
                        "".to_string()
                    } else {
                        format!(" {}", top.join(", "))
                    };

                    let opener = pick_variant(
                        &seed,
                        &[
                            "These functions are called by the most other code — changes here have the widest impact:",
                            "Based on the call graph, these are your most central functions:",
                            "Here are the most called functions (by caller count):",
                        ],
                    );

                    return format!("{}{}", opener, list);
                } else {
                    // File centrality: show file paths
                    let top: Vec<&str> = graph_context
                        .affected_files
                        .iter()
                        .filter_map(|r| r.path.as_deref())
                        .take(5)
                        .collect();

                    let list = if top.is_empty() {
                        "".to_string()
                    } else {
                        format!(" {}", top.join(", "))
                    };

                    let opener = pick_variant(
                        &seed,
                        &[
                            "These are the most connected files in your codebase — changes here ripple the furthest:",
                            "Based on the import graph, these files have the most connections:",
                            "Here are the most central files (by import count):",
                        ],
                    );

                    return format!("{}{}", opener, list);
                }
            }

            // Generic graph fallback.
            return format!(
                "I found some graph context around {}. If you want the full narrative, rerun with `--llm`.",
                target
            );
        }
    }

    // Fall back to findings/sessions based summary.
    if let Some(take) = build_no_llm_quick_take(response) {
        return take;
    }

    if !response.findings.is_empty() {
        let msg = pick_variant(
            &seed,
            &[
                "I pulled in a few relevant findings — worth a quick look.",
                "I found some related findings that should point you in the right direction.",
            ],
        );
        return msg.to_string();
    }

    if !response.sessions.is_empty() {
        // We have session context - summarize what we know
        let total_findings: i32 = response.sessions.iter().map(|s| s.total_findings).sum();

        if total_findings == 0 {
            return "Your codebase looks clean — no findings from the last review. That's a good sign!".to_string();
        }

        // Aggregate dimension counts across sessions
        let mut dim_totals: std::collections::HashMap<String, i32> =
            std::collections::HashMap::new();
        for session in &response.sessions {
            for (dim, count) in &session.dimension_counts {
                *dim_totals.entry(dim.clone()).or_insert(0) += count;
            }
        }

        if dim_totals.is_empty() {
            return format!(
                "I found {} finding(s) from your last review. Use `--verbose` to see details, or ask about a specific file or function.",
                total_findings
            );
        }

        // Format dimension summary
        let mut dims: Vec<(&String, &i32)> = dim_totals.iter().collect();
        dims.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending

        let dim_summary: String = dims
            .iter()
            .take(3)
            .map(|(dim, count)| format!("{} ({})", dim, count))
            .collect::<Vec<_>>()
            .join(", ");

        return format!(
            "From your last review: {} finding(s) across {}. Ask about a specific area or use `--verbose` for details.",
            total_findings, dim_summary
        );
    }

    let msg = pick_variant(
        &seed,
        &[
            "I couldn't find relevant context for this question.",
            "I don't have enough context to answer that cleanly yet.",
        ],
    );

    format!(
        "{} Try asking about specific code (e.g. 'what calls X?', 'impact of changing Y'), or use `--llm` for an AI-powered answer.",
        msg
    )
}

fn render_workspace_context(
    ctx: &RAGWorkspaceContext,
    graph_stats: Option<&std::collections::HashMap<String, i32>>,
    _verbose: bool,
) {
    println!("{}", "Workspace".bold());

    if let Some(kind) = &ctx.kind {
        if !kind.trim().is_empty() {
            println!("  {} {}", "Kind:".dimmed(), kind.bright_white());
        }
    }

    if !ctx.languages.is_empty() {
        let mut langs: Vec<(&String, &i32)> = ctx.languages.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));
        let s = langs
            .into_iter()
            .take(4)
            .map(|(l, c)| format!("{} ({})", l, c))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Languages:".dimmed(), s);
    }

    if !ctx.frameworks.is_empty() {
        println!("  {} {}", "Frameworks:".dimmed(), ctx.frameworks.join(", "));
    }

    if let Some(stats) = graph_stats {
        let file_count = stats.get("file_count").copied().unwrap_or(0);
        let fn_count = stats.get("function_count").copied().unwrap_or(0);
        let route_count = stats.get("route_count").copied().unwrap_or(0);
        if file_count > 0 || fn_count > 0 || route_count > 0 {
            println!(
                "  {} {} files, {} functions, {} routes",
                "Scale:".dimmed(),
                file_count,
                fn_count,
                route_count
            );
        }
    }

    if !ctx.entrypoints.is_empty() {
        println!(
            "  {} {}",
            "Entrypoints:".dimmed(),
            ctx.entrypoints
                .iter()
                .take(4)
                .map(|p| color_paths(p))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !ctx.central_files.is_empty() {
        let top = ctx
            .central_files
            .iter()
            .take(5)
            .map(|f| color_paths(&f.path))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Hotspots:".dimmed(), top);
    }

    if !ctx.top_dependencies.is_empty() {
        let deps = ctx
            .top_dependencies
            .iter()
            .take(8)
            .map(|d| d.name.clone())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Dependencies:".dimmed(), deps);
    }

    if !ctx.depended_on_by.is_empty() {
        let s = ctx
            .depended_on_by
            .iter()
            .take(6)
            .map(|w| {
                let name = w.package_name.as_deref().unwrap_or(w.workspace_id.as_str());
                format!("{} ({})", name, w.edge_count)
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Depended by:".dimmed(), s);
    }

    if !ctx.depends_on.is_empty() {
        let s = ctx
            .depends_on
            .iter()
            .take(6)
            .map(|w| {
                let name = w.package_name.as_deref().unwrap_or(w.workspace_id.as_str());
                format!("{} ({})", name, w.edge_count)
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Depends on:".dimmed(), s);
    }

    if !ctx.remote_servers.is_empty() {
        let remotes = ctx
            .remote_servers
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Outbound:".dimmed(), remotes);
    }
}

fn render_disambiguation(disambiguation: &RAGDisambiguation) {
    println!("{}", "Possible targets".bold());

    if let Some(msg) = &disambiguation.message {
        if !msg.trim().is_empty() {
            println!("{}", msg.dimmed());
        }
    }

    let mut idx: usize = 1;
    for token in &disambiguation.tokens {
        if disambiguation.tokens.len() > 1 {
            println!();
            println!("{} '{}'", "For".dimmed(), token.token.bold());
        }

        for cand in token.candidates.iter().take(10) {
            let display = cand
                .path
                .as_deref()
                .or(cand.qualified_name.as_deref())
                .or(cand.name.as_deref())
                .unwrap_or("<unknown>");

            let weak = if cand.is_weak { " (weak)" } else { "" };
            println!(
                "  {}. {} {}{}",
                idx,
                display,
                format!("[{}]", cand.node_type).dimmed(),
                weak.dimmed()
            );
            idx += 1;
        }

        if let Some(suggest) = token.candidates.iter().find_map(|c| c.rewrite.as_deref()) {
            println!("  {} {}", "Try:".dimmed(), suggest.bright_yellow());
        }
    }
}

fn build_no_llm_quick_take(response: &RAGQueryResponse) -> Option<String> {
    let seed = quick_take_seed(response);

    let has_flow_context = response
        .flow_context
        .as_ref()
        .is_some_and(|fc| !fc.paths.is_empty() || !fc.root_nodes.is_empty());

    let has_graph_context = response
        .graph_context
        .as_ref()
        .is_some_and(|gc| graph_context_has_data(gc));

    if has_flow_context {
        let fc = response.flow_context.as_ref().unwrap();
        if let Some(path) = fc.paths.first() {
            if let (Some(first), Some(last)) = (path.first(), path.last()) {
                let start = if let Some(p) = &first.path {
                    format!("{} ({})", first.name, p)
                } else {
                    first.name.clone()
                };
                let end = if let Some(p) = &last.path {
                    format!("{} ({})", last.name, p)
                } else {
                    last.name.clone()
                };

                let prefix = pick_variant(
                    &seed,
                    &[
                        "Here’s the shape I see:",
                        "At a glance it goes:",
                        "Roughly:",
                        "From what I can see:",
                        "The flow looks like:",
                        "A simple way to think about it:",
                    ],
                );

                if path.len() <= 2 {
                    return Some(format!("{} {} → {}.", prefix, start, end));
                }

                let mid = &path[1];
                let mid_s = if let Some(p) = &mid.path {
                    format!("{} ({})", mid.name, p)
                } else {
                    mid.name.clone()
                };

                return Some(format!("{} {} → {} → {}.", prefix, start, mid_s, end));
            }
        }

        if let Some(root) = fc.root_nodes.first() {
            let start = if let Some(p) = &root.path {
                format!("{} ({})", root.name, p)
            } else {
                root.name.clone()
            };
            let prefix = pick_variant(
                &seed,
                &[
                    "A reasonable starting point is",
                    "A good starting point is",
                    "If you want a starting point, try",
                    "I’d start with",
                ],
            );
            return Some(format!("{} {}.", prefix, start));
        }

        let msg = pick_variant(
            &seed,
            &[
                "I found a call flow, but it’s a bit sparse.",
                "I found a call flow, but it’s pretty thin.",
                "I found something, but it’s not a very rich path yet.",
            ],
        );
        return Some(msg.to_string());
    }

    if has_graph_context {
        let gc = response.graph_context.as_ref().unwrap();
        if gc.query_type == "dependencies" && !gc.dependencies.is_empty() {
            let msg = pick_variant(
                &seed,
                &[
                    "I found a few external dependencies that show up around your target.",
                    "A handful of external dependencies show up around your target.",
                    "There are a few external deps in the mix here.",
                ],
            );
            return Some(msg.to_string());
        }
        if !gc.library_users.is_empty() {
            let msg = pick_variant(
                &seed,
                &[
                    "I found a few places in the codebase that pull this in.",
                    "A few spots in the codebase seem to pull this in.",
                    "Looks like this gets pulled in from a few places.",
                ],
            );
            return Some(msg.to_string());
        }
        if !gc.affected_files.is_empty() {
            let msg = pick_variant(
                &seed,
                &[
                    "I found a small set of places that are affected by this change.",
                    "This change looks like it touches a small set of places.",
                    "There’s a small blast radius here.",
                ],
            );
            return Some(msg.to_string());
        }
    }

    if !response.findings.is_empty() {
        use std::collections::HashSet;

        // Deduplicate findings by (rule_id, file_path, line)
        let mut seen: HashSet<String> = HashSet::new();
        let mut deduped: Vec<&crate::api::rag::RAGFindingContext> = Vec::new();

        for f in &response.findings {
            let key = format!(
                "{}:{}:{}",
                f.rule_id.as_deref().unwrap_or(""),
                f.file_path.as_deref().unwrap_or(""),
                f.line.unwrap_or(0)
            );
            if seen.insert(key) {
                deduped.push(f);
            }
        }

        // Group findings by rule_id to give a more specific answer
        let mut rule_counts: HashMap<String, Vec<&crate::api::rag::RAGFindingContext>> =
            HashMap::new();
        for f in deduped {
            if let Some(rule_id) = &f.rule_id {
                rule_counts.entry(rule_id.clone()).or_default().push(f);
            }
        }

        // If we have specific rules, report on them directly
        if !rule_counts.is_empty() {
            let mut rules: Vec<(&String, &Vec<&crate::api::rag::RAGFindingContext>)> =
                rule_counts.iter().collect();
            rules.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

            if is_broad_health_query(&response.query) {
                let top_rules: Vec<String> = rules
                    .iter()
                    .take(3)
                    .map(|(r, fs)| format!("{} ({})", describe_rule_id(r), fs.len()))
                    .collect();

                let mut files: Vec<&str> = response
                    .findings
                    .iter()
                    .filter_map(|f| f.file_path.as_deref())
                    .collect();
                files.sort();
                files.dedup();
                let focus = if files.is_empty() {
                    "".to_string()
                } else if files.len() <= 3 {
                    format!(" Focus: {}.", files.join(", "))
                } else {
                    format!(
                        " Focus: {}, and {} more.",
                        files[..2].join(", "),
                        files.len() - 2
                    )
                };

                if top_rules.is_empty() {
                    return Some(format!(
                        "I found a few operability signals in this workspace.{}",
                        focus
                    ));
                }

                return Some(format!(
                    "A few things worth checking next: {}.{}",
                    top_rules.join(", "),
                    focus
                ));
            }

            // Build a response based on the top rules found
            let top_rule = rules[0].0;
            let top_findings = rules[0].1;
            let count = top_findings.len();

            // Get unique file paths for this rule
            let mut files: Vec<&str> = top_findings
                .iter()
                .filter_map(|f| f.file_path.as_deref())
                .collect();
            files.sort();
            files.dedup();

            // Format rule_id nicely (e.g., "python.http.missing_timeout" -> "HTTP calls missing timeout")
            let rule_desc = describe_rule_id(top_rule);

            let mut take = if count == 1 {
                format!("One place looks like it has {}", rule_desc)
            } else {
                format!("{} places look like they have {}", count, rule_desc)
            };

            // List affected files
            if !files.is_empty() {
                let file_list: String = if files.len() <= 3 {
                    files.join(", ")
                } else {
                    format!("{}, and {} more", files[..2].join(", "), files.len() - 2)
                };
                take.push_str(&format!(" in {}.", file_list));
            } else {
                take.push('.');
            }

            // If there are other rules, mention them
            if rules.len() > 1 {
                let other_rules: Vec<String> = rules[1..]
                    .iter()
                    .take(2)
                    .map(|(r, fs)| format!("{} ({})", describe_rule_id(r), fs.len()))
                    .collect();
                if !other_rules.is_empty() {
                    take.push_str(&format!(" Also found: {}.", other_rules.join(", ")));
                }
            }

            return Some(take);
        }

        // Fallback: just mention we found findings
        let count = response.findings.len();
        let best = response
            .findings
            .iter()
            .max_by(|a, b| a.similarity.partial_cmp(&b.similarity).unwrap());

        let mut take = format!("Found {} related finding(s)", count);
        if let Some(best) = best {
            if let Some(file) = &best.file_path {
                if let Some(line) = best.line {
                    take.push_str(&format!(". Best match: {}:{}.", file, line));
                } else {
                    take.push_str(&format!(". Best match: {}.", file));
                }
            }
        }
        return Some(take);
    }

    if response.sessions.is_empty() {
        return Some(
            "I couldn't find relevant context. Try asking about specific code, or use `--llm` for an AI-powered answer.".to_string()
        );
    }

    None
}

fn output_formatted(
    response: &RAGQueryResponse,
    llm_response: Option<&str>,
    verbose: bool,
    _has_llm: bool,
    streamed: bool,
) {
    let intent = classify_render_intent(response, llm_response);

    let has_graph_context = response
        .graph_context
        .as_ref()
        .is_some_and(|gc| graph_context_has_data(gc));

    let _has_structured_context = has_graph_context;

    // Print LLM response if available (this is the main answer)
    // If streamed=true, the response was already printed in real-time
    if llm_response.is_some() {
        if !streamed {
            // Non-streaming: print header and markdown-rendered response
            // Note: model info not available in output_formatted, shown in streaming path only
            println!();
            println!("{} {}", "🤖".green(), "AI Analysis".bold().underline());
            println!();

            // Render markdown with termimad (max 80 columns)
            if let Some(answer) = llm_response {
                render_markdown(answer);
            }
            println!();
        }

        // Show separator before raw context in verbose mode
        if verbose {
            println!();
            println!("{}", "─".repeat(50).dimmed());
            println!("{}", "Raw Context (verbose mode)".dimmed());
        }
    }

    // Default path: print a short colleague-style reply first.
    if llm_response.is_none() {
        let reply = build_colleague_reply(response);
        if !reply.trim().is_empty() {
            println!();
            for line in wrap_paragraph(&reply, MAX_ASK_WIDTH) {
                println!("{}", color_paths(&line));
            }
            println!();
        }
    }

    // If we have disambiguation candidates, render them as a list.
    if let Some(disambiguation) = &response.disambiguation {
        render_disambiguation(disambiguation);
        println!();
    }

    if let Some(workspace_ctx) = &response.workspace_context {
        if verbose {
            render_workspace_context(workspace_ctx, response.graph_stats.as_ref(), verbose);
            println!();
        } else if matches!(intent, RenderIntent::Overview | RenderIntent::Operability) {
            render_workspace_brief(workspace_ctx, response.graph_stats.as_ref());
            println!();
        }
    }

    if should_show_health_section(response, llm_response) {
        render_health_section(response);
        println!();
    }

    // If we have flow context, render it prominently (this is the "semantic" answer)
    if let Some(flow_context) = &response.flow_context {
        if !flow_context.paths.is_empty() || !flow_context.root_nodes.is_empty() {
            render_flow_context(flow_context, verbose);
            println!();
        }
    }

    // Render graph context (Usage, Impact, etc.) - this follows naturally from the summary
    if let Some(graph_context) = &response.graph_context {
        if graph_context_has_data(graph_context) {
            render_graph_context(graph_context, verbose);
            println!();
        }
    }

    // Show findings with code snippets (non-verbose mode)
    // Skip findings if we have good flow context - they're usually unrelated noise
    if should_show_worth_a_look(response, llm_response, verbose) {
        println!("{}", "Worth a look".bold());
        println!();
        render_findings_with_snippets(&response.findings);
    }

    // Render SLO context if present
    if let Some(slo_context) = &response.slo_context {
        if !slo_context.slos.is_empty() {
            render_slo_context(slo_context, verbose);
            println!();
        }
    }

    // Render enumerate context if present (for "how many routes" type queries)
    if let Some(enumerate_context) = &response.enumerate_context {
        render_enumerate_context(enumerate_context, verbose);
        println!();
    }

    // Print context summary (only in verbose mode when flow context is shown, or when no flow context)
    let show_summary = verbose;

    if show_summary {
        println!();
        println!("{}", "Context Summary".bold().underline());
        println!("{}", response.context_summary);
        println!();
    }

    // Print sessions if any (in verbose mode, or when no LLM answer and no flow context)
    let show_sessions = verbose && !response.sessions.is_empty();

    if show_sessions && !response.sessions.is_empty() {
        println!("{}", "Related Sessions".bold());
        println!("{}", "─".repeat(50).dimmed());

        for session in &response.sessions {
            let workspace = session.workspace_label.as_deref().unwrap_or("Unknown");
            // Similarity is inner product score, normalize to 0-100% for display
            // Scores > 1 indicate very high similarity, cap at 99%
            let similarity_pct = if session.similarity >= 1.0 {
                99
            } else {
                (session.similarity * 100.0).round() as i32
            };

            println!(
                "  {} {} {} ({}% match)",
                "•".cyan(),
                workspace.bright_white(),
                format!("[{} findings]", session.total_findings).dimmed(),
                similarity_pct
            );

            if verbose && !session.dimension_counts.is_empty() {
                let dims: Vec<String> = session
                    .dimension_counts
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                println!(
                    "    {} {}",
                    "Dimensions:".dimmed(),
                    dims.join(", ").dimmed()
                );
            }

            if verbose && !session.severity_counts.is_empty() {
                let sevs: Vec<String> = session
                    .severity_counts
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                println!(
                    "    {} {}",
                    "Severities:".dimmed(),
                    sevs.join(", ").dimmed()
                );
            }
        }
        println!();
    }

    // Print findings if any (in verbose mode, or when no LLM answer and no flow context)
    let show_findings = verbose && !response.findings.is_empty();

    if show_findings && !response.findings.is_empty() {
        println!("{}", "Related Findings".bold());
        println!("{}", "─".repeat(50).dimmed());

        for finding in &response.findings {
            let rule = finding.rule_id.as_deref().unwrap_or("unknown");
            let severity = finding.severity.as_deref().unwrap_or("unknown");
            let dimension = finding.dimension.as_deref().unwrap_or("unknown");
            // Similarity is inner product score, normalize to 0-100% for display
            let similarity_pct = if finding.similarity >= 1.0 {
                99
            } else {
                (finding.similarity * 100.0).round() as i32
            };

            // Color severity
            let severity_colored = match severity.to_lowercase().as_str() {
                "critical" | "high" => severity.red().bold(),
                "medium" => severity.yellow(),
                "low" => severity.green(),
                _ => severity.normal(),
            };

            println!(
                "  {} {} [{}] ({}% match)",
                "•".cyan(),
                rule.bright_white(),
                severity_colored,
                similarity_pct
            );

            if let (Some(file), Some(line)) = (&finding.file_path, finding.line) {
                println!("    {} {}:{}", "→".dimmed(), file.cyan(), line);
            } else if let Some(file) = &finding.file_path {
                println!("    {} {}", "→".dimmed(), file.cyan());
            }

            if verbose {
                println!("    {} {}", "Dimension:".dimmed(), dimension.dimmed());
            }
        }
        println!();
    }
}

/// Render findings with code snippets for a richer answer.
/// Shows the top findings grouped by rule with one example each.
fn render_findings_with_snippets(findings: &[crate::api::rag::RAGFindingContext]) {
    use std::collections::{HashMap, HashSet};

    // Deduplicate findings by (rule_id, file_path, line)
    let mut seen: HashSet<String> = HashSet::new();
    let mut deduped: Vec<&crate::api::rag::RAGFindingContext> = Vec::new();

    for f in findings {
        let key = format!(
            "{}:{}:{}",
            f.rule_id.as_deref().unwrap_or(""),
            f.file_path.as_deref().unwrap_or(""),
            f.line.unwrap_or(0)
        );
        if seen.insert(key) {
            deduped.push(f);
        }
    }

    // Group findings by rule_id
    let mut by_rule: HashMap<String, Vec<&crate::api::rag::RAGFindingContext>> = HashMap::new();
    for f in deduped {
        let rule = f.rule_id.clone().unwrap_or_else(|| "unknown".to_string());
        by_rule.entry(rule).or_default().push(f);
    }

    // Sort rules by count (most common first)
    let mut rules: Vec<_> = by_rule.into_iter().collect();
    rules.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    // Show up to 3 rules, with 1 example each
    for (rule_id, rule_findings) in rules.iter().take(3) {
        let rule_desc = describe_rule_id(rule_id);
        let count = rule_findings.len();

        // Show one example with code snippet
        if let Some(finding) = rule_findings.first() {
            if let (Some(file_path), Some(line)) = (&finding.file_path, finding.line) {
                let line_num = line as usize;

                // Print rule description and file:line reference
                let count_str = if count > 1 {
                    format!(" (+{} more)", count - 1)
                } else {
                    String::new()
                };

                println!(
                    "  {} {}:{} {}{}",
                    "→".cyan(),
                    file_path.cyan(),
                    line.to_string().yellow(),
                    rule_desc.dimmed(),
                    count_str.dimmed()
                );

                // Try to read the code snippet (just the target line)
                if let Ok(snippet) = read_code_snippet(file_path, line_num, 0) {
                    for (ln, code) in snippet {
                        let line_prefix = format!("{:>4} │", ln).dimmed();
                        // Trim leading whitespace and very long lines
                        let code_trimmed = code.trim_start();
                        let code_display = if code_trimmed.len() > 65 {
                            format!("{}...", &code_trimmed[..62])
                        } else {
                            code_trimmed.to_string()
                        };
                        println!("       {} {}", line_prefix, code_display.dimmed());
                    }
                }
            } else if let Some(file_path) = &finding.file_path {
                let count_str = if count > 1 {
                    format!(" (+{} more)", count - 1)
                } else {
                    String::new()
                };
                println!(
                    "  {} {} {}{}",
                    "→".cyan(),
                    file_path.cyan(),
                    rule_desc.dimmed(),
                    count_str.dimmed()
                );
            }
        }
    }
    println!();
}

/// Read a code snippet around a specific line.
/// Returns a vec of (line_number, line_content) tuples.
fn read_code_snippet(
    file_path: &str,
    target_line: usize,
    context: usize,
) -> std::io::Result<Vec<(usize, String)>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let start = target_line.saturating_sub(context);
    let end = target_line + context;

    let mut result = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line_num = idx + 1;
        if line_num >= start && line_num <= end {
            if let Ok(content) = line {
                result.push((line_num, content));
            }
        }
        if line_num > end {
            break;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_llm_quick_take_flow_context() {
        let response = RAGQueryResponse {
            query: "how does auth work".to_string(),
            sessions: vec![],
            findings: vec![],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: Some(RAGFlowContext {
                query: None,
                root_nodes: vec![],
                paths: vec![vec![
                    RAGFlowPathNode {
                        node_id: "n1".to_string(),
                        name: "start".to_string(),
                        path: Some("src/auth.go".to_string()),
                        node_type: "function".to_string(),
                        depth: 0,
                        http_method: None,
                        http_path: None,
                        description: None,
                        category: None,
                    },
                    RAGFlowPathNode {
                        node_id: "n2".to_string(),
                        name: "end".to_string(),
                        path: Some("src/db.go".to_string()),
                        node_type: "function".to_string(),
                        depth: 1,
                        http_method: None,
                        http_path: None,
                        description: None,
                        category: None,
                    },
                ]],
            }),
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        };

        let take = build_no_llm_quick_take(&response).unwrap();
        assert!(take.contains("→"));
        assert!(take.contains("src/auth.go"));

        let reply = build_colleague_reply(&response);
        assert!(reply.contains("flow") || reply.contains("path") || reply.contains("→"));
    }

    #[test]
    fn test_workspace_context_does_not_override_flow_reply_for_non_overview_queries() {
        let mut response = RAGQueryResponse {
            query: "what calls login?".to_string(),
            sessions: vec![],
            findings: vec![],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: Some(crate::api::rag::RAGFlowContext {
                query: Some("what calls login?".to_string()),
                root_nodes: vec![],
                paths: vec![vec![
                    crate::api::rag::RAGFlowPathNode {
                        node_id: "n1".to_string(),
                        name: "handler".to_string(),
                        path: Some("src/main.py".to_string()),
                        node_type: "function".to_string(),
                        depth: 0,
                        http_method: None,
                        http_path: None,
                        description: None,
                        category: None,
                    },
                    crate::api::rag::RAGFlowPathNode {
                        node_id: "n2".to_string(),
                        name: "login".to_string(),
                        path: Some("src/auth.py".to_string()),
                        node_type: "function".to_string(),
                        depth: 1,
                        http_method: None,
                        http_path: None,
                        description: None,
                        category: None,
                    },
                ]],
            }),
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        };

        response.workspace_context = Some(crate::api::rag::RAGWorkspaceContext {
            kind: Some("service".to_string()),
            languages: std::collections::HashMap::new(),
            frameworks: vec![],
            entrypoints: vec![],
            central_files: vec![],
            top_dependencies: vec![],
            depended_on_by: vec![],
            depends_on: vec![],
            remote_servers: vec![],
            summary: "This workspace looks like a service in python.".to_string(),
        });

        let reply = build_colleague_reply(&response);
        assert!(reply.contains("→"), "unexpected reply: {reply}");
        assert!(!reply.contains("This workspace looks"));
    }

    #[test]
    fn test_no_llm_quick_take_findings() {
        let response = RAGQueryResponse {
            query: "what should I worry about".to_string(),
            sessions: vec![],
            findings: vec![crate::api::rag::RAGFindingContext {
                finding_id: "f1".to_string(),
                rule_id: Some("security.hardcoded_secret".to_string()),
                dimension: Some("Security".to_string()),
                severity: Some("High".to_string()),
                file_path: Some("src/main.go".to_string()),
                line: Some(10),
                similarity: 0.9,
            }],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: None,
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        };

        let take = build_no_llm_quick_take(&response).unwrap();
        let lower = take.to_lowercase();
        assert!(
            lower.contains("hardcoded secrets"),
            "expected 'hardcoded secrets' in: {}",
            lower
        );
        assert!(lower.contains("src/main.go"));

        let reply = build_colleague_reply(&response);
        assert!(!reply.trim().is_empty());
    }

    #[test]
    fn test_workspace_overview_query_detection() {
        assert!(is_workspace_overview_query("Describe this workspace"));
        assert!(is_workspace_overview_query("workspace overview"));
        assert!(is_workspace_overview_query(
            "give me an overview of this repo"
        ));
        assert!(!is_workspace_overview_query("where is this used"));
    }

    #[test]
    fn test_health_section_shown_for_broad_health_query() {
        let response = RAGQueryResponse {
            query: "How is this service doing in prod?".to_string(),
            sessions: vec![],
            findings: vec![
                crate::api::rag::RAGFindingContext {
                    finding_id: "f1".to_string(),
                    rule_id: Some("python.http.missing_timeout".to_string()),
                    dimension: Some("Reliability".to_string()),
                    severity: Some("Medium".to_string()),
                    file_path: Some("src/main.py".to_string()),
                    line: Some(10),
                    similarity: 0.9,
                },
                crate::api::rag::RAGFindingContext {
                    finding_id: "f2".to_string(),
                    rule_id: Some("python.http.missing_timeout".to_string()),
                    dimension: Some("Reliability".to_string()),
                    severity: Some("Medium".to_string()),
                    file_path: Some("src/worker.py".to_string()),
                    line: Some(42),
                    similarity: 0.8,
                },
            ],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: None,
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        };

        assert!(should_show_health_section(&response, None));
        // For broad health queries, we should not default to dumping findings.
        assert!(!should_show_worth_a_look(&response, None, false));

        let take = build_no_llm_quick_take(&response).unwrap();
        let lower = take.to_lowercase();
        assert!(
            lower.contains("worth checking") || lower.contains("worth checking next"),
            "unexpected take: {take}"
        );
    }

    #[test]
    fn test_health_section_hidden_when_workspace_context_present() {
        let response = RAGQueryResponse {
            query: "How is this service doing in prod?".to_string(),
            sessions: vec![],
            findings: vec![],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: None,
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: Some(crate::api::rag::RAGWorkspaceContext {
                kind: Some("service".to_string()),
                languages: std::collections::HashMap::new(),
                frameworks: vec![],
                entrypoints: vec![],
                central_files: vec![],
                top_dependencies: vec![],
                depended_on_by: vec![],
                depends_on: vec![],
                remote_servers: vec![],
                summary: "This workspace looks like a service in python.".to_string(),
            }),
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        };

        assert!(!should_show_health_section(&response, None));
    }

    #[test]
    fn test_non_health_query_softened_finding_phrasing() {
        let response = RAGQueryResponse {
            query: "missing request timeout".to_string(),
            sessions: vec![],
            findings: vec![crate::api::rag::RAGFindingContext {
                finding_id: "f1".to_string(),
                rule_id: Some("python.http.missing_timeout".to_string()),
                dimension: Some("Reliability".to_string()),
                severity: Some("Medium".to_string()),
                file_path: Some("src/main.py".to_string()),
                line: Some(10),
                similarity: 0.9,
            }],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: None,
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        };

        let take = build_no_llm_quick_take(&response).unwrap();
        assert!(take.to_lowercase().contains("one place"));
        assert!(!take.to_lowercase().contains("found 1 instance"));
    }

    #[test]
    fn test_golden_questions_routing_smoke() {
        let cases = vec![
            ("Describe this workspace", true, false),
            ("workspace overview", true, false),
            ("How is this service doing in prod?", false, true),
            ("Is this production ready?", false, true),
            ("what calls login?", false, false),
            ("list routes", false, false),
        ];

        for (q, expect_overview, expect_health) in cases {
            assert_eq!(
                is_workspace_overview_query(q),
                expect_overview,
                "workspace_overview for '{q}'"
            );
            assert_eq!(
                is_broad_health_query(q),
                expect_health,
                "broad_health for '{q}'"
            );
        }
    }

    #[test]
    fn test_classify_render_intent_basics() {
        let base = RAGQueryResponse {
            query: "Describe this workspace".to_string(),
            sessions: vec![],
            findings: vec![],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: None,
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        };

        // Flow beats everything.
        let mut r = base.clone();
        r.flow_context = Some(crate::api::rag::RAGFlowContext {
            query: Some("what calls login?".to_string()),
            root_nodes: vec![],
            paths: vec![vec![crate::api::rag::RAGFlowPathNode {
                node_id: "n1".to_string(),
                name: "login".to_string(),
                path: Some("src/auth.py".to_string()),
                node_type: "function".to_string(),
                depth: 0,
                http_method: None,
                http_path: None,
                description: None,
                category: None,
            }]],
        });
        assert_eq!(classify_render_intent(&r, None), RenderIntent::Flow);

        // Enumerate.
        let mut r = base.clone();
        r.enumerate_context = Some(crate::api::rag::RAGEnumerateContext {
            query_target: "routes".to_string(),
            count: 1,
            items: vec![],
            truncated: false,
            summary: "Found 1 route".to_string(),
        });
        assert_eq!(classify_render_intent(&r, None), RenderIntent::Enumerate);

        // Observability.
        let mut r = base.clone();
        r.slo_context = Some(crate::api::rag::RAGSloContext {
            monitored_routes: vec![],
            unmonitored_routes: vec![],
            slos: vec![crate::api::rag::RAGSloInfo {
                id: "1".to_string(),
                name: "slo".to_string(),
                provider: "gcp".to_string(),
                path_pattern: None,
                http_method: None,
                target_percent: Some(99.9),
                current_percent: None,
                error_budget_remaining: None,
                timeframe: None,
                dashboard_url: None,
            }],
            summary: Some("ok".to_string()),
        });
        assert_eq!(
            classify_render_intent(&r, None),
            RenderIntent::Observability
        );

        // Workspace overview when workspace_context is present.
        let mut r = base.clone();
        r.workspace_context = Some(crate::api::rag::RAGWorkspaceContext {
            kind: Some("service".to_string()),
            languages: std::collections::HashMap::new(),
            frameworks: vec![],
            entrypoints: vec![],
            central_files: vec![],
            top_dependencies: vec![],
            depended_on_by: vec![],
            depends_on: vec![],
            remote_servers: vec![],
            summary: "This workspace looks like a service".to_string(),
        });
        assert_eq!(classify_render_intent(&r, None), RenderIntent::Overview);

        // Findings fallback.
        let mut r = base;
        r.query = "what should I worry about".to_string();
        r.findings = vec![crate::api::rag::RAGFindingContext {
            finding_id: "f1".to_string(),
            rule_id: Some("python.http.missing_timeout".to_string()),
            dimension: Some("Reliability".to_string()),
            severity: Some("Medium".to_string()),
            file_path: Some("src/main.py".to_string()),
            line: Some(10),
            similarity: 0.9,
        }];
        assert_eq!(classify_render_intent(&r, None), RenderIntent::Findings);
    }

    #[test]
    fn test_ask_args_defaults() {
        let args = AskArgs {
            query: "test query".to_string(),
            workspace_id: None,
            workspace_path: None,
            max_sessions: None,
            max_findings: None,
            similarity_threshold: None,
            json: false,
            llm: false,
            verbose: false,
        };
        assert_eq!(args.query, "test query");
        assert!(args.workspace_id.is_none());
        assert!(args.workspace_path.is_none());
        assert!(!args.json);
        assert!(!args.llm);
        assert!(!args.verbose);
    }

    #[test]
    fn test_colleague_reply_prefers_hint() {
        let response = RAGQueryResponse {
            query: "where is it used".to_string(),
            sessions: vec![],
            findings: vec![],
            sources: vec![],
            context_summary: "".to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: None,
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: Some("Please specify a file path or symbol".to_string()),
            disambiguation: None,
        };

        let reply = build_colleague_reply(&response);
        assert!(reply.to_lowercase().contains("please"));
        assert!(reply.to_lowercase().contains("specify"));
    }

    #[test]
    fn test_ask_args_with_options() {
        let args = AskArgs {
            query: "How is my service?".to_string(),
            workspace_id: Some("wks_abc123".to_string()),
            workspace_path: Some("/path/to/project".to_string()),
            max_sessions: Some(10),
            max_findings: Some(20),
            similarity_threshold: Some(0.7),
            json: true,
            llm: true,
            verbose: true,
        };
        assert_eq!(args.query, "How is my service?");
        assert_eq!(args.workspace_id, Some("wks_abc123".to_string()));
        assert_eq!(args.workspace_path, Some("/path/to/project".to_string()));
        assert_eq!(args.max_sessions, Some(10));
        assert!(args.json);
        assert!(args.verbose);
        assert!(args.llm);
    }
}

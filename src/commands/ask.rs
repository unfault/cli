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
    ClientGraphData, RAGFlowContext, RAGFlowPathNode, RAGGraphContext, RAGQueryRequest,
    RAGQueryResponse,
};
use crate::config::Config;
use crate::exit_codes::*;
use crate::session::{
    MetaFileInfo, SerializableGraph, build_local_graph, compute_workspace_id, get_git_remote,
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

    ClientGraphData {
        files,
        functions,
        calls,
        imports,
        contains,
        library_usage,
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
    /// Skip LLM and show raw context only
    pub no_llm: bool,
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
                Some(graph_to_client_data(&graph))
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

    // Check if LLM is configured for generating AI response (unless --no-llm)
    let llm_response = if !args.no_llm && config.llm_ready() {
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
    // Create a combined response with LLM output if available
    let output = if let Some(llm_text) = llm_response {
        serde_json::json!({
            "query": response.query,
            "answer": llm_text,
            "sessions": response.sessions,
            "findings": response.findings,
            "sources": response.sources,
            "context_summary": response.context_summary,
        })
    } else {
        serde_json::to_value(response)?
    };

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
            // Regular function node: show as "calls function_name()"
            if indent == 0 {
                format!("{}calls {}()", indent_str, node.name.yellow())
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
    println!("Analyzing code graph...");
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
        } else if name.starts_with("handle_") {
            &name[7..]
        } else if name.starts_with("create_") {
            &name[7..]
        } else if name.starts_with("delete_") {
            &name[7..]
        } else if name.starts_with("update_") {
            &name[7..]
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
        "library" => "Library usage",
        "dependencies" => "External dependencies",
        other => other,
    };

    println!("{} {}", "📈".cyan(), title.bold());

    if ctx.query_type == "impact" {
        let target = ctx.target_file.as_deref().unwrap_or("target");
        if ctx.affected_files.is_empty() {
            println!("  {} No callers found for {}", "ℹ".blue(), target.cyan());
        } else {
            println!(
                "  {} Functions/files that depend on {}:",
                "→".cyan(),
                target.cyan()
            );
            for (idx, rel) in ctx.affected_files.iter().enumerate() {
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
        }
    }

    if ctx.query_type == "library" && !ctx.library_users.is_empty() {
        println!();
        println!("  {} Files using target library:", "→".cyan());
        for (idx, rel) in ctx.library_users.iter().enumerate() {
            let path = rel.path.as_deref().unwrap_or("<unknown>");
            let relationship = rel.relationship.as_deref().unwrap_or("imports");
            println!(
                "  {} {} ({} {} )",
                format!("{}.", idx + 1).bright_white(),
                path.cyan(),
                relationship,
                rel.usage.as_deref().unwrap_or("")
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

    if verbose {
        println!();
        println!(
            "{} target: {}",
            "Target".dimmed(),
            ctx.target_file.as_deref().unwrap_or("n/a").dimmed()
        );
    }
}

fn output_formatted(
    response: &RAGQueryResponse,
    llm_response: Option<&str>,
    verbose: bool,
    has_llm: bool,
    streamed: bool,
) {
    // Check if we have flow context (indicates a "how does X work?" type query)
    let has_flow_context = response
        .flow_context
        .as_ref()
        .is_some_and(|fc| !fc.paths.is_empty() || !fc.root_nodes.is_empty());

    let has_graph_context = response
        .graph_context
        .as_ref()
        .is_some_and(|gc| graph_context_has_data(gc));

    let has_structured_context = has_flow_context || has_graph_context;

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
    } else if !has_llm {
        // No LLM configured - show hint at top, but AFTER flow context if present
        if !has_structured_context {
            println!();
            println!(
                "{} {} Configure an LLM for AI-powered answers: {}",
                "💡".yellow(),
                "Tip:".yellow().bold(),
                "unfault config llm openai".cyan()
            );
        }
    }

    // If we have flow context, render it prominently (this is the "semantic" answer)
    if let Some(flow_context) = &response.flow_context {
        if !flow_context.paths.is_empty() || !flow_context.root_nodes.is_empty() {
            render_flow_context(flow_context, verbose);
            println!();

            // Show LLM hint after flow context (when no LLM configured)
            if llm_response.is_none() && !has_llm {
                println!(
                    "{} {} Configure an LLM for AI-powered answers: {}",
                    "💡".yellow(),
                    "Tip:".yellow().bold(),
                    "unfault config llm openai".cyan()
                );
            }
        }
    }

    if let Some(graph_context) = &response.graph_context {
        if graph_context_has_data(graph_context) {
            render_graph_context(graph_context, verbose);
            println!();
        }
    }

    // Print context summary (only in verbose mode when flow context is shown, or when no flow context)
    let show_summary = if has_structured_context {
        verbose // Only show in verbose when we have flow context
    } else {
        llm_response.is_none() || verbose
    };

    if show_summary {
        println!();
        println!("{}", "Context Summary".bold().underline());
        println!("{}", response.context_summary);
        println!();
    }

    // Print sessions if any (in verbose mode, or when no LLM answer and no flow context)
    let show_sessions = if has_structured_context {
        verbose
    } else {
        (llm_response.is_none() || verbose) && !response.sessions.is_empty()
    };

    if show_sessions && !response.sessions.is_empty() {
        println!("{}", "Related Sessions".bold());
        println!("{}", "─".repeat(50).dimmed());

        for session in &response.sessions {
            let workspace = session.workspace_label.as_deref().unwrap_or("Unknown");
            let similarity_pct = (session.similarity * 100.0).round() as i32;

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
    let show_findings = if has_structured_context {
        verbose
    } else {
        (llm_response.is_none() || verbose) && !response.findings.is_empty()
    };

    if show_findings && !response.findings.is_empty() {
        println!("{}", "Related Findings".bold());
        println!("{}", "─".repeat(50).dimmed());

        for finding in &response.findings {
            let rule = finding.rule_id.as_deref().unwrap_or("unknown");
            let severity = finding.severity.as_deref().unwrap_or("unknown");
            let dimension = finding.dimension.as_deref().unwrap_or("unknown");
            let similarity_pct = (finding.similarity * 100.0).round() as i32;

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

    // If nothing found (only show when no LLM answer AND no flow context)
    if llm_response.is_none()
        && !has_structured_context
        && response.sessions.is_empty()
        && response.findings.is_empty()
    {
        println!("{} No relevant context found for your query.", "ℹ".blue());
        println!("  Try running `unfault review` first to analyze your code.");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            no_llm: false,
            verbose: false,
        };
        assert_eq!(args.query, "test query");
        assert!(args.workspace_id.is_none());
        assert!(args.workspace_path.is_none());
        assert!(!args.json);
        assert!(!args.no_llm);
        assert!(!args.verbose);
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
            no_llm: false,
            verbose: true,
        };
        assert_eq!(args.query, "How is my service?");
        assert_eq!(args.workspace_id, Some("wks_abc123".to_string()));
        assert_eq!(args.workspace_path, Some("/path/to/project".to_string()));
        assert_eq!(args.max_sessions, Some(10));
        assert!(args.json);
        assert!(args.verbose);
    }
}

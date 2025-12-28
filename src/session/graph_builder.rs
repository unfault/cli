//! Local code graph building using unfault-core.
//!
//! This module provides functionality to parse source files and build
//! a code graph locally (without sending source code to the API).
//! Only the resulting graph JSON is sent to the API for analysis.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;

use unfault_core::graph::{CodeGraph, GraphEdgeKind, GraphNode, build_code_graph};
use unfault_core::parse::ast::FileId;
use unfault_core::parse::{go, python, rust as rust_parse, typescript};
use unfault_core::semantics::SourceSemantics;
use unfault_core::semantics::go::model::GoFileSemantics;
use unfault_core::semantics::python::model::PyFileSemantics;
use unfault_core::semantics::rust::{build_rust_semantics, model::RustFileSemantics};
use unfault_core::semantics::typescript::model::TsFileSemantics;
use unfault_core::types::context::{Language, SourceFile};

/// A serializable representation of the code graph for sending to the API.
#[derive(Debug, serde::Serialize)]
pub struct SerializableGraph {
    /// Total number of nodes in the graph
    pub node_count: usize,
    /// Total number of edges in the graph
    pub edge_count: usize,
    /// File nodes with their paths
    pub files: Vec<FileNode>,
    /// Function nodes
    pub functions: Vec<FunctionNode>,
    /// Import edges (file → file)
    pub imports: Vec<ImportEdge>,
    /// Contains edges (file → function/class)
    pub contains: Vec<ContainsEdge>,
    /// Call edges (function → function)
    pub calls: Vec<CallEdge>,
    /// External library usage
    pub library_usage: Vec<LibraryUsage>,
    /// Graph statistics
    pub stats: GraphStats,
}

#[derive(Debug, serde::Serialize)]
pub struct FileNode {
    pub path: String,
    pub language: String,
}

#[derive(Debug, serde::Serialize)]
pub struct FunctionNode {
    pub name: String,
    pub qualified_name: String,
    pub file_path: String,
    pub is_async: bool,
    pub is_handler: bool,
    /// HTTP method if this is an HTTP route handler (e.g., "GET", "POST")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// HTTP path if this is an HTTP route handler (e.g., "/users/{user_id}")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct ImportEdge {
    pub from_file: String,
    pub to_file: String,
    /// Items imported (for `from X import Y` style)
    pub items: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct ContainsEdge {
    pub file_path: String,
    pub item_name: String,
    pub item_type: String, // "function", "class", etc.
}

#[derive(Debug, serde::Serialize)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub caller_file: String,
}

#[derive(Debug, serde::Serialize)]
pub struct LibraryUsage {
    pub file_path: String,
    pub library: String,
}

#[derive(Debug, serde::Serialize)]
pub struct GraphStats {
    pub file_count: usize,
    pub function_count: usize,
    pub class_count: usize,
    pub import_edge_count: usize,
    pub calls_edge_count: usize,
}

/// Build a code graph from files in a directory.
///
/// This function:
/// 1. Discovers source files in the directory
/// 2. Parses each file using tree-sitter
/// 3. Extracts semantics (imports, functions, calls)
/// 4. Builds a unified code graph
///
/// # Arguments
/// * `workspace_path` - Path to the workspace directory
/// * `file_paths` - Optional list of specific files to include (if None, discover all)
/// * `verbose` - Enable verbose logging
pub fn build_local_graph(
    workspace_path: &Path,
    file_paths: Option<&[PathBuf]>,
    verbose: bool,
) -> Result<SerializableGraph> {
    let mut semantics_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();
    let mut file_id_counter: u64 = 1;

    // Determine files to process
    let files = match file_paths {
        Some(paths) => paths.to_vec(),
        None => discover_source_files(workspace_path)?,
    };

    if verbose {
        eprintln!("Building graph from {} files...", files.len());
    }

    // Parse and extract semantics from each file
    for file_path in &files {
        let Some(language) = detect_language(file_path) else {
            continue;
        };

        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let relative_path = file_path
            .strip_prefix(workspace_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let file_id = FileId(file_id_counter);
        file_id_counter += 1;

        let source_file = SourceFile {
            path: relative_path.clone(),
            language,
            content,
        };

        // Parse and build semantics based on language
        let semantics = match language {
            Language::Python => {
                let parsed = match python::parse_python_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let mut sem = PyFileSemantics::from_parsed(&parsed);
                // Analyze frameworks (FastAPI, etc.)
                let _ = sem.analyze_frameworks(&parsed);
                Arc::new(SourceSemantics::Python(sem))
            }
            Language::Go => {
                let parsed = match go::parse_go_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let mut sem = GoFileSemantics::from_parsed(&parsed);
                // Analyze frameworks (Gin, etc.)
                let _ = sem.analyze_frameworks(&parsed);
                Arc::new(SourceSemantics::Go(sem))
            }
            Language::Rust => {
                let parsed = match rust_parse::parse_rust_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                // Use build_rust_semantics to fully analyze the file (collect functions, etc.)
                let sem = match build_rust_semantics(&parsed) {
                    Ok(s) => s,
                    Err(_) => RustFileSemantics::from_parsed(&parsed),
                };
                Arc::new(SourceSemantics::Rust(sem))
            }
            Language::Typescript => {
                let parsed = match typescript::parse_typescript_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let mut sem = TsFileSemantics::from_parsed(&parsed);
                // Analyze frameworks (Express, etc.)
                let _ = sem.analyze_frameworks(&parsed);
                Arc::new(SourceSemantics::Typescript(sem))
            }
            _ => continue,
        };

        semantics_entries.push((file_id, semantics));
    }

    if verbose {
        eprintln!("Parsed {} files successfully", semantics_entries.len());
    }

    // Build the code graph
    let code_graph = build_code_graph(&semantics_entries);

    // Serialize to our API-compatible format
    Ok(serialize_graph(&code_graph))
}

/// Discover source files in a directory using ignore patterns.
fn discover_source_files(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    use ignore::WalkBuilder;

    let mut files = Vec::new();

    let walker = WalkBuilder::new(workspace_path)
        .hidden(true)
        .git_ignore(true)
        .git_exclude(true)
        .build();

    for entry in walker {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && detect_language(path).is_some() {
            files.push(path.to_path_buf());
        }
    }

    Ok(files)
}

/// Detect language from file extension.
fn detect_language(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "py" => Some(Language::Python),
        "go" => Some(Language::Go),
        "rs" => Some(Language::Rust),
        "ts" | "tsx" | "js" | "jsx" => Some(Language::Typescript),
        _ => None,
    }
}

/// Serialize a CodeGraph to our API-compatible JSON format.
fn serialize_graph(graph: &CodeGraph) -> SerializableGraph {
    let mut files = Vec::new();
    let mut functions = Vec::new();
    let mut imports = Vec::new();
    let mut contains = Vec::new();
    let mut calls = Vec::new();
    let mut library_usage = Vec::new();

    // Build a map from FileId to path for file nodes
    let mut file_id_to_path: std::collections::HashMap<FileId, String> =
        std::collections::HashMap::new();

    // Extract nodes - iterate over all node indices
    for node_idx in graph.graph.node_indices() {
        let node = &graph.graph[node_idx];
        match node {
            GraphNode::File {
                file_id,
                path,
                language,
                ..
            } => {
                file_id_to_path.insert(*file_id, path.clone());
                files.push(FileNode {
                    path: path.clone(),
                    language: format!("{:?}", language),
                });
            }
            GraphNode::Function {
                name,
                qualified_name,
                is_async,
                is_handler,
                file_id,
                http_method,
                http_path,
            } => {
                // Find the file path for this function
                let file_path = file_id_to_path.get(file_id).cloned().unwrap_or_default();

                functions.push(FunctionNode {
                    name: name.clone(),
                    qualified_name: qualified_name.clone(),
                    file_path,
                    is_async: *is_async,
                    is_handler: *is_handler,
                    http_method: http_method.clone(),
                    http_path: http_path.clone(),
                });
            }
            _ => {}
        }
    }

    // Extract edges - iterate over all edge indices
    for edge_idx in graph.graph.edge_indices() {
        let (source_idx, target_idx) = graph.graph.edge_endpoints(edge_idx).unwrap();
        let edge_kind = &graph.graph[edge_idx];

        match edge_kind {
            GraphEdgeKind::Imports => {
                let from_path = get_file_path(&graph.graph[source_idx], &file_id_to_path);
                let to_path = get_file_path(&graph.graph[target_idx], &file_id_to_path);

                if let (Some(from_path), Some(to_path)) = (from_path, to_path) {
                    imports.push(ImportEdge {
                        from_file: from_path,
                        to_file: to_path,
                        items: vec![],
                    });
                }
            }
            GraphEdgeKind::ImportsFrom { items } => {
                let from_path = get_file_path(&graph.graph[source_idx], &file_id_to_path);
                let to_path = get_file_path(&graph.graph[target_idx], &file_id_to_path);

                if let (Some(from_path), Some(to_path)) = (from_path, to_path) {
                    imports.push(ImportEdge {
                        from_file: from_path,
                        to_file: to_path,
                        items: items.clone(),
                    });
                }
            }
            GraphEdgeKind::Contains => {
                let source_node = &graph.graph[source_idx];
                let target_node = &graph.graph[target_idx];

                let source_path = get_file_path(source_node, &file_id_to_path);
                let (item_name, item_type) = match target_node {
                    GraphNode::Function { name, .. } => (name.clone(), "function"),
                    GraphNode::Class { name, .. } => (name.clone(), "class"),
                    _ => continue,
                };

                if let Some(file_path) = source_path {
                    contains.push(ContainsEdge {
                        file_path,
                        item_name,
                        item_type: item_type.to_string(),
                    });
                }
            }
            GraphEdgeKind::Calls => {
                let source_node = &graph.graph[source_idx];
                let target_node = &graph.graph[target_idx];

                // Both source and target should be function nodes
                let (caller_name, caller_file) = match source_node {
                    GraphNode::Function {
                        qualified_name,
                        file_id,
                        ..
                    } => {
                        let file_path = file_id_to_path.get(file_id).cloned().unwrap_or_default();
                        (qualified_name.clone(), file_path)
                    }
                    _ => continue,
                };
                let callee_name = match target_node {
                    GraphNode::Function { qualified_name, .. } => qualified_name.clone(),
                    _ => continue,
                };
                calls.push(CallEdge {
                    caller: caller_name,
                    callee: callee_name,
                    caller_file,
                });
            }
            GraphEdgeKind::UsesLibrary => {
                let source_node = &graph.graph[source_idx];
                let target_node = &graph.graph[target_idx];

                let file_path = get_file_path(source_node, &file_id_to_path);
                let library_name = match target_node {
                    GraphNode::ExternalModule { name, .. } => name.clone(),
                    _ => continue,
                };

                if let Some(file_path) = file_path {
                    library_usage.push(LibraryUsage {
                        file_path,
                        library: library_name,
                    });
                }
            }
            _ => {}
        }
    }

    let graph_stats = graph.stats();

    SerializableGraph {
        node_count: graph.graph.node_count(),
        edge_count: graph.graph.edge_count(),
        files,
        functions,
        imports,
        contains,
        calls,
        library_usage,
        stats: GraphStats {
            file_count: graph_stats.file_count,
            function_count: graph_stats.function_count,
            class_count: graph_stats.class_count,
            import_edge_count: graph_stats.import_edge_count,
            calls_edge_count: graph_stats.calls_edge_count,
        },
    }
}

/// Helper to get file path from a node
fn get_file_path(
    node: &GraphNode,
    file_id_to_path: &std::collections::HashMap<FileId, String>,
) -> Option<String> {
    match node {
        GraphNode::File { path, .. } => Some(path.clone()),
        GraphNode::Function { file_id, .. }
        | GraphNode::Class { file_id, .. }
        | GraphNode::FastApiApp { file_id, .. }
        | GraphNode::FastApiRoute { file_id, .. }
        | GraphNode::FastApiMiddleware { file_id, .. } => file_id_to_path.get(file_id).cloned(),
        GraphNode::ExternalModule { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_detect_language() {
        assert_eq!(
            detect_language(Path::new("test.py")),
            Some(Language::Python)
        );
        assert_eq!(detect_language(Path::new("test.go")), Some(Language::Go));
        assert_eq!(detect_language(Path::new("test.rs")), Some(Language::Rust));
        assert_eq!(
            detect_language(Path::new("test.ts")),
            Some(Language::Typescript)
        );
        assert_eq!(
            detect_language(Path::new("test.tsx")),
            Some(Language::Typescript)
        );
        assert_eq!(detect_language(Path::new("test.txt")), None);
    }

    #[test]
    fn test_build_local_graph_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let result = build_local_graph(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.node_count, 0);
        assert_eq!(graph.edge_count, 0);
    }

    #[test]
    fn test_build_local_graph_python_file() {
        let temp_dir = TempDir::new().unwrap();
        let py_file = temp_dir.path().join("test.py");
        fs::write(
            &py_file,
            r#"
def hello():
    pass

def caller():
    hello()
"#,
        )
        .unwrap();

        let result = build_local_graph(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let graph = result.unwrap();

        // Should have 1 file
        assert_eq!(graph.files.len(), 1);
        assert_eq!(graph.files[0].path, "test.py");

        // Should have 2 functions
        assert_eq!(graph.functions.len(), 2);
        let func_names: Vec<&str> = graph.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(func_names.contains(&"hello"));
        assert!(func_names.contains(&"caller"));
    }

    #[test]
    fn test_build_local_graph_with_imports() {
        let temp_dir = TempDir::new().unwrap();

        // Create a module structure
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();

        fs::write(
            src_dir.join("main.py"),
            r#"
from src.utils import helper

def main():
    helper()
"#,
        )
        .unwrap();

        fs::write(
            src_dir.join("utils.py"),
            r#"
def helper():
    print("hello")
"#,
        )
        .unwrap();

        let result = build_local_graph(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let graph = result.unwrap();

        // Should have 2 files
        assert_eq!(graph.files.len(), 2);

        // Should have functions
        assert!(graph.functions.len() >= 2);
    }

    #[test]
    fn test_serializable_graph_json() {
        let temp_dir = TempDir::new().unwrap();
        let py_file = temp_dir.path().join("test.py");
        fs::write(
            &py_file,
            r#"
import requests

def fetch_data():
    return requests.get("http://example.com")
"#,
        )
        .unwrap();

        let result = build_local_graph(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let graph = result.unwrap();

        // Should be serializable to JSON
        let json = serde_json::to_string(&graph);
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("test.py"));
        assert!(json_str.contains("fetch_data"));
    }

    #[test]
    fn test_build_local_graph_relative_import() {
        let temp_dir = TempDir::new().unwrap();

        // Create utils.py
        fs::write(
            temp_dir.path().join("utils.py"),
            r#"
def add(a, b):
    return a + b
"#,
        )
        .unwrap();

        // Create app.py that imports from .utils
        fs::write(
            temp_dir.path().join("app.py"),
            r#"
from .utils import add

def main():
    return add(1, 2)
"#,
        )
        .unwrap();

        let result = build_local_graph(temp_dir.path(), None, true);
        assert!(result.is_ok());
        let graph = result.unwrap();

        // Should have 2 files
        assert_eq!(graph.files.len(), 2);

        // Should have an import edge from app.py to utils.py
        assert!(
            graph.stats.import_edge_count >= 1,
            "Expected at least 1 import edge from .utils import, got {}",
            graph.stats.import_edge_count
        );

        // Check the import edge
        let relative_import = graph.imports.iter().find(|i|
            i.from_file == "app.py" && i.to_file == "utils.py"
        );
        assert!(
            relative_import.is_some(),
            "Expected import edge from app.py to utils.py, found: {:?}",
            graph.imports
        );
    }
}

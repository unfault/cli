//! Client-side IR (Intermediate Representation) builder.
//!
//! This module provides functionality to parse source files locally and build
//! a complete IR containing semantics and a code graph. The IR can then be
//! serialized and sent to the API for rule evaluation, without sending
//! source code over the wire.
//!
//! ## Architecture
//!
//! The client-side parsing flow:
//! 1. Discover source files in the workspace
//! 2. Parse each file using tree-sitter (via unfault-core)
//! 3. Extract language-specific semantics (imports, functions, calls, etc.)
//! 4. Build a unified code graph
//! 5. Package into IntermediateRepresentation
//! 6. Serialize to JSON and send to API
//!
//! ## Example
//!
//! ```rust,ignore
//! use unfault::session::ir_builder::build_ir;
//!
//! let ir = build_ir(&workspace_path, None, false)?;
//! let ir_json = serde_json::to_string(&ir)?;
//!
//! // Send ir_json to POST /v1/graph/analyze
//! ```

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use colored::Colorize;
use log::debug;
use rayon::prelude::*;

use unfault_core::IntermediateRepresentation;
use unfault_core::graph::build_code_graph;
use unfault_core::parse::ast::FileId;
use unfault_core::parse::{go, python, rust as rust_parse, typescript};
use unfault_core::semantics::SourceSemantics;
use unfault_core::semantics::go::model::GoFileSemantics;
use unfault_core::semantics::python::model::PyFileSemantics;
use unfault_core::semantics::rust::model::RustFileSemantics;
use unfault_core::semantics::typescript::model::TsFileSemantics;
use unfault_core::types::context::{Language, SourceFile};

use super::semantics_cache::{CacheStats, SemanticsCache};

/// Result of building IR with cache statistics
#[derive(Debug)]
pub struct IrBuildResult {
    /// The built intermediate representation
    pub ir: IntermediateRepresentation,
    /// Cache statistics (hits, misses, etc.)
    pub cache_stats: CacheStats,
}

/// Build an Intermediate Representation from files in a directory.
///
/// This function:
/// 1. Discovers source files in the directory
/// 2. Parses each file using tree-sitter
/// 3. Extracts semantics (imports, functions, calls)
/// 4. Builds a unified code graph
/// 5. Returns a serializable IntermediateRepresentation
///
/// # Arguments
///
/// * `workspace_path` - Path to the workspace directory
/// * `file_paths` - Optional list of specific files to include (if None, discover all)
/// * `verbose` - Enable verbose logging
///
/// # Returns
///
/// An [`IntermediateRepresentation`] containing semantics for each file and
/// a code graph representing the relationships between code elements.
///
/// # Example
///
/// ```rust,ignore
/// use unfault::session::ir_builder::build_ir;
///
/// // Build IR for all files in workspace
/// let ir = build_ir(&workspace_path, None, false)?;
///
/// // Build IR for specific files only
/// let files = vec![PathBuf::from("src/main.py"), PathBuf::from("src/utils.py")];
/// let ir = build_ir(&workspace_path, Some(&files), true)?;
/// ```
pub fn build_ir(
    workspace_path: &Path,
    file_paths: Option<&[PathBuf]>,
    verbose: bool,
) -> Result<IntermediateRepresentation> {
    // Determine files to process
    let files = match file_paths {
        Some(paths) => paths.to_vec(),
        None => discover_source_files(workspace_path)?,
    };

    if verbose {
        eprintln!("Building IR from {} files...", files.len());
    }

    // Parse and extract semantics from each file in parallel
    let results: Vec<Option<(FileId, SourceSemantics)>> = files
        .par_iter()
        .enumerate()
        .map(|(index, file_path)| {
            let language = detect_language(file_path)?;

            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: Could not read {}: {}", file_path.display(), e);
                    }
                    return None;
                }
            };

            let relative_path = file_path
                .strip_prefix(workspace_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let file_id = FileId((index + 1) as u64);

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
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let mut sem = PyFileSemantics::from_parsed(&parsed);
                    // Analyze frameworks (FastAPI, etc.)
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Python(sem)
                }
                Language::Go => {
                    let parsed = match go::parse_go_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let mut sem = GoFileSemantics::from_parsed(&parsed);
                    // Analyze frameworks (Gin, etc.)
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Go(sem)
                }
                Language::Rust => {
                    let parsed = match rust_parse::parse_rust_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let sem = RustFileSemantics::from_parsed(&parsed);
                    SourceSemantics::Rust(sem)
                }
                Language::Typescript => {
                    let parsed = match typescript::parse_typescript_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let mut sem = TsFileSemantics::from_parsed(&parsed);
                    // Analyze frameworks (Express, etc.)
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Typescript(sem)
                }
                _ => {
                    if verbose {
                        eprintln!(
                            "Skipping unsupported language for {}: {:?}",
                            relative_path, language
                        );
                    }
                    return None;
                }
            };

            Some((file_id, semantics))
        })
        .collect();

    let mut semantics_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();
    let mut all_semantics: Vec<SourceSemantics> = Vec::new();

    for (file_id, semantics) in results.into_iter().flatten() {
        all_semantics.push(semantics.clone());
        semantics_entries.push((file_id, Arc::new(semantics)));
    }

    if verbose {
        eprintln!("Parsed {} files successfully", semantics_entries.len());
    }

    // Build the code graph
    let code_graph = build_code_graph(&semantics_entries);

    if verbose {
        let stats = code_graph.stats();
        eprintln!(
            "Built graph: {} files, {} functions, {} imports, {} library usages",
            stats.file_count,
            stats.function_count,
            stats.import_edge_count,
            stats.uses_library_edge_count
        );
    }

    Ok(IntermediateRepresentation::new(all_semantics, code_graph))
}

/// Build an Intermediate Representation with caching support.
///
/// Similar to [`build_ir`], but uses a file-based cache to skip re-parsing
/// files that haven't changed. On incremental runs, this can reduce parse
/// time from ~2000ms to ~50-100ms.
///
/// # Arguments
///
/// * `workspace_path` - Path to the workspace directory
/// * `file_paths` - Optional list of specific files to include
/// * `verbose` - Enable verbose logging
///
/// # Returns
///
/// An [`IrBuildResult`] containing the IR and cache statistics.
///
/// # Example
///
/// ```rust,ignore
/// use unfault::session::ir_builder::build_ir_cached;
///
/// let result = build_ir_cached(&workspace_path, None, false)?;
/// println!("Cache hit rate: {:.1}%", result.cache_stats.hit_rate());
/// let ir_json = serde_json::to_string(&result.ir)?;
/// ```
pub fn build_ir_cached(
    workspace_path: &Path,
    file_paths: Option<&[PathBuf]>,
    verbose: bool,
) -> Result<IrBuildResult> {
    let _total_start = Instant::now();

    // Open or create the cache
    let cache_start = Instant::now();
    let cache = SemanticsCache::open(workspace_path)?;
    let cache = Arc::new(Mutex::new(cache));
    let cache_open_ms = cache_start.elapsed().as_millis();

    // Determine files to process
    let discover_start = Instant::now();
    let files = match file_paths {
        Some(paths) => paths.to_vec(),
        None => discover_source_files(workspace_path)?,
    };
    let discover_ms = discover_start.elapsed().as_millis();

    if verbose {
        eprintln!("Building IR from {} files (with cache)...", files.len());
        eprintln!(
            "{} Cache open: {}ms, File discovery: {}ms",
            "TIMING".yellow(),
            cache_open_ms,
            discover_ms
        );
    }

    // Parse and extract semantics from each file in parallel, using cache
    let parse_start = Instant::now();
    let results: Vec<Option<(FileId, SourceSemantics)>> = files
        .par_iter()
        .enumerate()
        .map(|(index, file_path)| {
            let language = detect_language(file_path)?;

            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: Could not read {}: {}", file_path.display(), e);
                    }
                    return None;
                }
            };

            let relative_path = file_path
                .strip_prefix(workspace_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let file_id = FileId((index + 1) as u64);

            // Compute content hash
            let content_hash = SemanticsCache::hash_content(&content);

            // Try cache first
            {
                let mut cache_guard = cache.lock().unwrap();
                if let Some(cached_semantics) = cache_guard.get(&relative_path, content_hash) {
                    return Some((file_id, cached_semantics));
                }
            }

            let source_file = SourceFile {
                path: relative_path.clone(),
                language,
                content: content.clone(),
            };

            // Parse and build semantics based on language
            let semantics = match language {
                Language::Python => {
                    let parsed = match python::parse_python_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let mut sem = PyFileSemantics::from_parsed(&parsed);
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Python(sem)
                }
                Language::Go => {
                    let parsed = match go::parse_go_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let mut sem = GoFileSemantics::from_parsed(&parsed);
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Go(sem)
                }
                Language::Rust => {
                    let parsed = match rust_parse::parse_rust_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let sem = RustFileSemantics::from_parsed(&parsed);
                    SourceSemantics::Rust(sem)
                }
                Language::Typescript => {
                    let parsed = match typescript::parse_typescript_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let mut sem = TsFileSemantics::from_parsed(&parsed);
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Typescript(sem)
                }
                _ => {
                    if verbose {
                        eprintln!(
                            "Skipping unsupported language for {}: {:?}",
                            relative_path, language
                        );
                    }
                    return None;
                }
            };

            // Store in cache
            {
                let mut cache_guard = cache.lock().unwrap();
                cache_guard.set(&relative_path, content_hash, &semantics);
            }

            Some((file_id, semantics))
        })
        .collect();
    let parse_ms = parse_start.elapsed().as_millis();

    let mut semantics_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();
    let mut all_semantics: Vec<SourceSemantics> = Vec::new();

    for (file_id, semantics) in results.into_iter().flatten() {
        all_semantics.push(semantics.clone());
        semantics_entries.push((file_id, Arc::new(semantics)));
    }

    // Get final cache stats
    let cache_stats = cache.lock().unwrap().stats().clone();

    if verbose {
        eprintln!(
            "Parsed {} files (cache: {} hits, {} misses, {:.1}% hit rate)",
            semantics_entries.len(),
            cache_stats.hits,
            cache_stats.misses,
            cache_stats.hit_rate()
        );
        eprintln!("{} File read + cache: {}ms", "TIMING".yellow(), parse_ms);
    }

    // Build the code graph
    let graph_start = Instant::now();
    let code_graph = build_code_graph(&semantics_entries);
    let graph_ms = graph_start.elapsed().as_millis();

    let stats = code_graph.stats();
    if verbose {
        eprintln!(
            "Built graph: {} files, {} functions, {} imports, {} library usages",
            stats.file_count,
            stats.function_count,
            stats.import_edge_count,
            stats.uses_library_edge_count
        );
        eprintln!("{} Graph build: {}ms", "TIMING".yellow(), graph_ms);
    }

    // Log detailed graph information
    debug!("[GRAPH] Graph statistics:");
    debug!("  - Total nodes: {}", code_graph.graph.node_count());
    debug!("  - Total edges: {}", code_graph.graph.edge_count());
    debug!("  - File nodes: {}", stats.file_count);
    debug!("  - Function nodes: {}", stats.function_count);
    debug!("  - Class nodes: {}", stats.class_count);
    debug!("  - Import edges: {}", stats.import_edge_count);
    debug!("  - Contains edges: {}", stats.contains_edge_count);
    debug!("  - Uses library edges: {}", stats.uses_library_edge_count);
    debug!("  - Calls edges: {}", stats.calls_edge_count);
    debug!("  - External modules: {}", stats.external_module_count);

    // Create IR and log serialization details
    let ir = IntermediateRepresentation::new(all_semantics, code_graph);

    let serialization_start = Instant::now();
    match serde_json::to_string(&ir) {
        Ok(json) => {
            let json_size = json.len();
            let json_size_mb = json_size as f64 / (1024.0 * 1024.0);
            let serialization_ms = serialization_start.elapsed().as_millis();
            debug!("[GRAPH] Serialization details:");
            debug!(
                "  - JSON size: {} bytes ({:.2} MB)",
                json_size, json_size_mb
            );
            debug!("  - Serialization time: {}ms", serialization_ms);
            debug!("  - Semantics count: {}", ir.semantics.len());
        }
        Err(e) => {
            debug!("[GRAPH] Failed to serialize IR: {}", e);
        }
    }

    Ok(IrBuildResult { ir, cache_stats })
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
    fn test_build_ir_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.file_count(), 0);
    }

    #[test]
    fn test_build_ir_python_file() {
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

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Should have 1 file
        assert_eq!(ir.file_count(), 1);

        // Should have functions in the graph
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 2);
    }

    #[test]
    fn test_build_ir_with_imports() {
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

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Should have 2 files
        assert_eq!(ir.file_count(), 2);

        // Should have functions
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 2);
    }

    #[test]
    fn test_ir_serialization() {
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

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Should be serializable to JSON
        let json = serde_json::to_string(&ir);
        assert!(json.is_ok());
        let json_str = json.unwrap();

        // JSON should contain expected content
        assert!(json_str.contains("fetch_data"));
        assert!(json_str.contains("requests"));
    }

    #[test]
    fn test_ir_deserialization_and_rebuild() {
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

        let ir = build_ir(temp_dir.path(), None, false).unwrap();

        // Serialize
        let json = serde_json::to_string(&ir).unwrap();

        // Deserialize
        let mut ir_restored: IntermediateRepresentation = serde_json::from_str(&json).unwrap();

        // Rebuild indexes (required after deserialization)
        ir_restored.rebuild_graph_indexes();

        // Stats should match
        let stats_before = ir.graph.stats();
        let stats_after = ir_restored.graph.stats();
        assert_eq!(stats_before.file_count, stats_after.file_count);
        assert_eq!(stats_before.function_count, stats_after.function_count);
        assert_eq!(
            stats_before.external_module_count,
            stats_after.external_module_count
        );
    }

    #[test]
    fn test_build_ir_with_specific_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple files
        let file1 = temp_dir.path().join("include.py");
        let file2 = temp_dir.path().join("exclude.py");
        fs::write(&file1, "def included(): pass").unwrap();
        fs::write(&file2, "def excluded(): pass").unwrap();

        // Build IR with only specific files
        let files = vec![file1];
        let ir = build_ir(temp_dir.path(), Some(&files), false).unwrap();

        // Should only have 1 file
        assert_eq!(ir.file_count(), 1);

        // Check that only the included function is in the graph
        let stats = ir.graph.stats();
        assert_eq!(stats.function_count, 1);
    }

    #[test]
    fn test_build_ir_go_file() {
        let temp_dir = TempDir::new().unwrap();
        let go_file = temp_dir.path().join("main.go");
        fs::write(
            &go_file,
            r#"
package main

import "fmt"

func main() {
    fmt.Println("Hello")
}
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        assert_eq!(ir.file_count(), 1);
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 1);
    }

    #[test]
    fn test_build_ir_typescript_file() {
        let temp_dir = TempDir::new().unwrap();
        let ts_file = temp_dir.path().join("app.ts");
        fs::write(
            &ts_file,
            r#"
import express from 'express';

function handler(req: any, res: any) {
    res.json({ ok: true });
}
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        assert_eq!(ir.file_count(), 1);
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 1);
    }

    #[test]
    fn test_build_ir_rust_file() {
        let temp_dir = TempDir::new().unwrap();
        let rs_file = temp_dir.path().join("lib.rs");
        fs::write(
            &rs_file,
            r#"
use std::io;

fn process_data() -> io::Result<()> {
    Ok(())
}
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Rust semantics builder currently uses from_parsed() which creates an empty structure.
        // The full Rust analyzer populates functions separately. For now, we just verify
        // that the file is parsed without error and included in the IR.
        assert_eq!(ir.file_count(), 1);
        let stats = ir.graph.stats();
        assert_eq!(stats.file_count, 1);
        // Note: stats.function_count may be 0 until Rust semantics extraction is fully implemented
    }
}

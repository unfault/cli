//! # File Collector
//!
//! Collects files from a workspace based on file hints returned by the API.
//! File hints contain predicates that specify which files to include/exclude.
//!
//! Uses rayon for parallel file processing to improve performance on large workspaces.
//! Optimized to minimize mutex contention using gather-scatter patterns and atomic counters.

use anyhow::Result;
use glob::Pattern;
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::api::{FilePredicate, FileQueryHint, SourceFile};
use crate::session::workspace::Language;

/// Collected files ready for analysis.
#[derive(Debug, Clone)]
pub struct CollectedFiles {
    /// Files collected for analysis
    pub files: Vec<SourceFile>,
    /// Total bytes of all files
    pub total_bytes: usize,
    /// Number of files skipped due to limits
    pub skipped_count: usize,
}

/// Collector for selecting files based on file hints.
pub struct FileCollector {
    root: PathBuf,
}

impl FileCollector {
    /// Create a new file collector.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory of the workspace
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Collect files based on file hints.
    ///
    /// # Arguments
    ///
    /// * `hints` - File query hints from the API
    /// * `source_files` - Pre-scanned source files from workspace
    ///
    /// # Returns
    ///
    /// * `Ok(CollectedFiles)` - Collected files
    /// * `Err(_)` - Failed to collect files
    pub fn collect(
        &self,
        hints: &[FileQueryHint],
        source_files: &[(PathBuf, Language)],
    ) -> Result<CollectedFiles> {
        // Track seen paths for deduplication (sequential access only)
        let mut seen_paths: HashSet<String> = HashSet::new();
        let mut all_files: Vec<SourceFile> = Vec::new();
        let mut total_bytes: usize = 0;

        // Process hints sequentially (hint processing is already parallelized internally)
        for hint in hints {
            let hint_files = self.collect_for_hint(hint, source_files)?;

            // Deduplicate and accumulate (no mutex needed - sequential)
            for file in hint_files {
                if !seen_paths.contains(&file.path) {
                    total_bytes += file.contents.len();
                    seen_paths.insert(file.path.clone());
                    all_files.push(file);
                }
            }
        }

        // If no hints provided OR no files matched any hints, collect all source files
        // This is a fallback to ensure we always have files to analyze when source files exist
        if hints.is_empty() || (all_files.is_empty() && !source_files.is_empty()) {
            // Use atomic counter for skipped files (lock-free)
            let skipped_count = AtomicUsize::new(0);

            // Gather phase: parallel file reading with no shared mutable state
            // Each thread returns its own Vec, avoiding mutex contention
            let collected: Vec<Option<SourceFile>> = source_files
                .par_iter()
                .map(|(path, language)| {
                    let relative_path = path
                        .strip_prefix(&self.root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .to_string();

                    // Skip if already seen (from hints processing)
                    if seen_paths.contains(&relative_path) {
                        return None;
                    }

                    match fs::read_to_string(path) {
                        Ok(contents) => Some(SourceFile {
                            path: relative_path,
                            language: language.as_str().to_string(),
                            contents,
                        }),
                        Err(_) => {
                            skipped_count.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                    }
                })
                .collect();

            // Scatter phase: sequential merge with deduplication (no contention)
            for file in collected.into_iter().flatten() {
                if !seen_paths.contains(&file.path) {
                    total_bytes += file.contents.len();
                    seen_paths.insert(file.path.clone());
                    all_files.push(file);
                }
            }

            return Ok(CollectedFiles {
                files: all_files,
                total_bytes,
                skipped_count: skipped_count.load(Ordering::Relaxed),
            });
        }

        Ok(CollectedFiles {
            files: all_files,
            total_bytes,
            skipped_count: 0,
        })
    }

    /// Collect files for a single hint using parallel processing.
    fn collect_for_hint(
        &self,
        hint: &FileQueryHint,
        source_files: &[(PathBuf, Language)],
    ) -> Result<Vec<SourceFile>> {
        let max_files = hint.max_files.unwrap_or(i32::MAX) as usize;
        let max_bytes = hint.max_total_bytes.unwrap_or(i64::MAX);

        // Check if any predicate needs file content
        let needs_content = hint
            .include
            .iter()
            .chain(hint.exclude.iter())
            .any(|p| Self::predicate_needs_content(p));

        // First pass: parallel filtering and reading
        let candidates: Vec<_> = source_files
            .par_iter()
            .filter_map(|(path, language)| {
                let relative_path = path
                    .strip_prefix(&self.root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();

                // Read file contents once if any predicate needs it or for the final result
                // We read early to avoid double-reading for content-based predicates
                let contents = if needs_content {
                    // Read once for both predicate matching and result
                    fs::read_to_string(path).ok()?
                } else {
                    String::new() // Placeholder, will read later if file passes filter
                };

                // Check include predicates (all must match)
                if !hint.include.is_empty() {
                    let all_match = hint.include.iter().all(|p| {
                        self.matches_predicate_with_content(p, &relative_path, language, &contents)
                    });

                    if !all_match {
                        return None;
                    }
                }

                // Check exclude predicates (any match excludes)
                let any_exclude = hint.exclude.iter().any(|p| {
                    self.matches_predicate_with_content(p, &relative_path, language, &contents)
                });

                if any_exclude {
                    return None;
                }

                // If we didn't read contents yet (no content predicates), read now
                let final_contents = if needs_content {
                    contents
                } else {
                    fs::read_to_string(path).ok()?
                };

                Some(SourceFile {
                    path: relative_path,
                    language: language.as_str().to_string(),
                    contents: final_contents,
                })
            })
            .collect();

        // Second pass: sequential limit enforcement (maintains deterministic ordering)
        let mut files = Vec::new();
        let mut total_bytes = 0i64;

        for file in candidates {
            if files.len() >= max_files {
                break;
            }

            let file_bytes = file.contents.len() as i64;
            if total_bytes + file_bytes > max_bytes {
                continue;
            }

            total_bytes += file_bytes;
            files.push(file);
        }

        Ok(files)
    }

    /// Check if a predicate needs file content to evaluate.
    fn predicate_needs_content(predicate: &FilePredicate) -> bool {
        matches!(
            predicate.kind.as_str(),
            "text_contains_any" | "text_contains_all" | "text_matches_regex"
        )
    }

    /// Check if a file matches a predicate, using pre-read content for text predicates.
    fn matches_predicate_with_content(
        &self,
        predicate: &FilePredicate,
        relative_path: &str,
        language: &Language,
        contents: &str,
    ) -> bool {
        match predicate.kind.as_str() {
            "language" => {
                if let Some(ref value) = predicate.value {
                    language.as_str() == value
                } else {
                    false
                }
            }
            "path_glob" => {
                if let Some(ref pattern) = predicate.pattern {
                    match Pattern::new(pattern) {
                        Ok(glob) => glob.matches(relative_path),
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            "under_directory" => {
                if let Some(ref value) = predicate.value {
                    relative_path.starts_with(value)
                } else {
                    false
                }
            }
            "text_contains_any" => {
                if let Some(ref values) = predicate.values {
                    values.iter().any(|v| contents.contains(v))
                } else {
                    false
                }
            }
            "text_contains_all" => {
                if let Some(ref values) = predicate.values {
                    values.iter().all(|v| contents.contains(v))
                } else {
                    false
                }
            }
            "text_matches_regex" => {
                if let Some(ref pattern) = predicate.pattern {
                    if let Ok(regex) = Regex::new(pattern) {
                        regex.is_match(contents)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Collect all source files without filtering.
    ///
    /// # Arguments
    ///
    /// * `source_files` - Pre-scanned source files from workspace
    ///
    /// # Returns
    ///
    /// * `Ok(CollectedFiles)` - All collected files
    /// * `Err(_)` - Failed to collect files
    pub fn collect_all(&self, source_files: &[(PathBuf, Language)]) -> Result<CollectedFiles> {
        self.collect(&[], source_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn test_collect_all_files() {
        let temp_dir = TempDir::new().unwrap();
        let path1 = create_test_file(temp_dir.path(), "main.py", "print('hello')");
        let path2 = create_test_file(temp_dir.path(), "lib.py", "def foo(): pass");

        let source_files = vec![(path1, Language::Python), (path2, Language::Python)];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect_all(&source_files).unwrap();

        assert_eq!(result.files.len(), 2);
        assert!(result.files.iter().any(|f| f.path == "main.py"));
        assert!(result.files.iter().any(|f| f.path == "lib.py"));
    }

    #[test]
    fn test_collect_with_language_predicate() {
        let temp_dir = TempDir::new().unwrap();
        let py_path = create_test_file(temp_dir.path(), "main.py", "print('hello')");
        let rs_path = create_test_file(temp_dir.path(), "main.rs", "fn main() {}");

        let source_files = vec![(py_path, Language::Python), (rs_path, Language::Rust)];

        let hints = vec![FileQueryHint {
            id: "python_files".to_string(),
            label: Some("Python files".to_string()),
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "language".to_string(),
                value: Some("python".to_string()),
                pattern: None,
                values: None,
            }],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "main.py");
        assert_eq!(result.files[0].language, "python");
    }

    #[test]
    fn test_collect_with_path_glob_predicate() {
        let temp_dir = TempDir::new().unwrap();
        let main_path = create_test_file(temp_dir.path(), "main.py", "print('hello')");
        let test_path = create_test_file(temp_dir.path(), "test_main.py", "def test(): pass");

        let source_files = vec![(main_path, Language::Python), (test_path, Language::Python)];

        let hints = vec![FileQueryHint {
            id: "test_files".to_string(),
            label: Some("Test files".to_string()),
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "path_glob".to_string(),
                value: None,
                pattern: Some("test_*.py".to_string()),
                values: None,
            }],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "test_main.py");
    }

    #[test]
    fn test_collect_with_under_directory_predicate() {
        let temp_dir = TempDir::new().unwrap();
        let src_path = create_test_file(temp_dir.path(), "src/main.py", "print('hello')");
        let root_path = create_test_file(temp_dir.path(), "main.py", "print('root')");

        let source_files = vec![(src_path, Language::Python), (root_path, Language::Python)];

        let hints = vec![FileQueryHint {
            id: "src_files".to_string(),
            label: Some("Source files".to_string()),
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "under_directory".to_string(),
                value: Some("src".to_string()),
                pattern: None,
                values: None,
            }],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].path.starts_with("src"));
    }

    #[test]
    fn test_collect_with_text_contains_any_predicate() {
        let temp_dir = TempDir::new().unwrap();
        let fastapi_path = create_test_file(
            temp_dir.path(),
            "app.py",
            "from fastapi import FastAPI\napp = FastAPI()",
        );
        let plain_path = create_test_file(temp_dir.path(), "utils.py", "def helper(): pass");

        let source_files = vec![
            (fastapi_path, Language::Python),
            (plain_path, Language::Python),
        ];

        let hints = vec![FileQueryHint {
            id: "fastapi_files".to_string(),
            label: Some("FastAPI files".to_string()),
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "text_contains_any".to_string(),
                value: None,
                pattern: None,
                values: Some(vec![
                    "from fastapi".to_string(),
                    "import fastapi".to_string(),
                ]),
            }],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "app.py");
    }

    #[test]
    fn test_collect_with_exclude_predicate() {
        let temp_dir = TempDir::new().unwrap();
        let main_path = create_test_file(temp_dir.path(), "main.py", "print('hello')");
        let test_path = create_test_file(temp_dir.path(), "test_main.py", "def test(): pass");

        let source_files = vec![(main_path, Language::Python), (test_path, Language::Python)];

        let hints = vec![FileQueryHint {
            id: "non_test_files".to_string(),
            label: Some("Non-test files".to_string()),
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "language".to_string(),
                value: Some("python".to_string()),
                pattern: None,
                values: None,
            }],
            exclude: vec![FilePredicate {
                kind: "path_glob".to_string(),
                value: None,
                pattern: Some("test_*.py".to_string()),
                values: None,
            }],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "main.py");
    }

    #[test]
    fn test_collect_with_max_files_limit() {
        let temp_dir = TempDir::new().unwrap();
        let path1 = create_test_file(temp_dir.path(), "a.py", "pass");
        let path2 = create_test_file(temp_dir.path(), "b.py", "pass");
        let path3 = create_test_file(temp_dir.path(), "c.py", "pass");

        let source_files = vec![
            (path1, Language::Python),
            (path2, Language::Python),
            (path3, Language::Python),
        ];

        let hints = vec![FileQueryHint {
            id: "limited".to_string(),
            label: None,
            max_files: Some(2),
            max_total_bytes: None,
            include: vec![],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 2);
    }

    #[test]
    fn test_collect_with_max_bytes_limit() {
        let temp_dir = TempDir::new().unwrap();
        let path1 = create_test_file(temp_dir.path(), "small.py", "x=1");
        let path2 = create_test_file(temp_dir.path(), "large.py", "x=1\n".repeat(1000).as_str());

        let source_files = vec![(path1, Language::Python), (path2, Language::Python)];

        let hints = vec![FileQueryHint {
            id: "limited".to_string(),
            label: None,
            max_files: None,
            max_total_bytes: Some(100),
            include: vec![],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        // Only the small file should be included
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "small.py");
    }

    #[test]
    fn test_collect_deduplicates_files() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_file(temp_dir.path(), "main.py", "print('hello')");

        let source_files = vec![(path, Language::Python)];

        // Two hints that would both match the same file
        let hints = vec![
            FileQueryHint {
                id: "hint1".to_string(),
                label: None,
                max_files: None,
                max_total_bytes: None,
                include: vec![],
                exclude: vec![],
            },
            FileQueryHint {
                id: "hint2".to_string(),
                label: None,
                max_files: None,
                max_total_bytes: None,
                include: vec![],
                exclude: vec![],
            },
        ];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        // File should only appear once
        assert_eq!(result.files.len(), 1);
    }

    #[test]
    fn test_collect_with_text_matches_regex_predicate() {
        let temp_dir = TempDir::new().unwrap();
        let async_path = create_test_file(
            temp_dir.path(),
            "async_handler.py",
            "async def handle():\n    await something()",
        );
        let sync_path = create_test_file(temp_dir.path(), "sync_handler.py", "def handle(): pass");

        let source_files = vec![
            (async_path, Language::Python),
            (sync_path, Language::Python),
        ];

        let hints = vec![FileQueryHint {
            id: "async_files".to_string(),
            label: Some("Async files".to_string()),
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "text_matches_regex".to_string(),
                value: None,
                pattern: Some(r"async\s+def".to_string()),
                values: None,
            }],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "async_handler.py");
    }

    #[test]
    fn test_collect_with_text_contains_all_predicate() {
        let temp_dir = TempDir::new().unwrap();
        let both_path = create_test_file(
            temp_dir.path(),
            "both.py",
            "from fastapi import FastAPI\nfrom pydantic import BaseModel",
        );
        let one_path = create_test_file(temp_dir.path(), "one.py", "from fastapi import FastAPI");

        let source_files = vec![(both_path, Language::Python), (one_path, Language::Python)];

        let hints = vec![FileQueryHint {
            id: "fastapi_pydantic".to_string(),
            label: None,
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "text_contains_all".to_string(),
                value: None,
                pattern: None,
                values: Some(vec!["fastapi".to_string(), "pydantic".to_string()]),
            }],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "both.py");
    }

    #[test]
    fn test_total_bytes_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let content1 = "print('hello')";
        let content2 = "print('world')";
        let path1 = create_test_file(temp_dir.path(), "a.py", content1);
        let path2 = create_test_file(temp_dir.path(), "b.py", content2);

        let source_files = vec![(path1, Language::Python), (path2, Language::Python)];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect_all(&source_files).unwrap();

        assert_eq!(result.total_bytes, content1.len() + content2.len());
    }

    #[test]
    fn test_collect_falls_back_when_no_hints_match() {
        // This tests the fallback behavior: when hints exist but match no files,
        // we should still collect all source files
        let temp_dir = TempDir::new().unwrap();
        let path1 = create_test_file(temp_dir.path(), "main.rs", "fn main() {}");
        let path2 = create_test_file(temp_dir.path(), "lib.rs", "pub fn helper() {}");

        let source_files = vec![(path1, Language::Rust), (path2, Language::Rust)];

        // Hints that won't match any files (looking for axum patterns that don't exist)
        let hints = vec![FileQueryHint {
            id: "axum_handlers".to_string(),
            label: Some("Axum handlers".to_string()),
            max_files: None,
            max_total_bytes: None,
            include: vec![
                FilePredicate {
                    kind: "language".to_string(),
                    value: Some("rust".to_string()),
                    pattern: None,
                    values: None,
                },
                FilePredicate {
                    kind: "text_contains_any".to_string(),
                    value: None,
                    pattern: None,
                    values: Some(vec!["axum::".to_string(), "use axum".to_string()]),
                },
            ],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        // Should fall back to collecting all source files since hints matched nothing
        assert_eq!(result.files.len(), 2);
        assert!(result.files.iter().any(|f| f.path == "main.rs"));
        assert!(result.files.iter().any(|f| f.path == "lib.rs"));
    }

    #[test]
    fn test_collect_no_fallback_when_hints_match() {
        // When hints match some files, we should NOT fall back to all files
        let temp_dir = TempDir::new().unwrap();
        let fastapi_path = create_test_file(
            temp_dir.path(),
            "app.py",
            "from fastapi import FastAPI\napp = FastAPI()",
        );
        let plain_path = create_test_file(temp_dir.path(), "utils.py", "def helper(): pass");

        let source_files = vec![
            (fastapi_path, Language::Python),
            (plain_path, Language::Python),
        ];

        // Hint that matches only fastapi files
        let hints = vec![FileQueryHint {
            id: "fastapi_files".to_string(),
            label: None,
            max_files: None,
            max_total_bytes: None,
            include: vec![FilePredicate {
                kind: "text_contains_any".to_string(),
                value: None,
                pattern: None,
                values: Some(vec!["from fastapi".to_string()]),
            }],
            exclude: vec![],
        }];

        let collector = FileCollector::new(temp_dir.path());
        let result = collector.collect(&hints, &source_files).unwrap();

        // Should only include the FastAPI file, not fall back
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "app.py");
    }
}

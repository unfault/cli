use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::workspace_id::{
    MetaFileInfo as WorkspaceIdMetaFile, WorkspaceIdSource, get_git_remote,
    get_or_compute_workspace_id,
};
use super::workspace_settings::{LoadedSettings, WorkspaceSettings, load_settings};
use crate::api::{AdvertisedProfile, MetaFile, ProjectLayout, WorkspaceDescriptor};

/// Progress update during workspace scanning.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Number of source files found so far
    pub file_count: usize,
    /// Detected languages so far
    pub languages: Vec<String>,
    /// Detected frameworks so far
    pub frameworks: Vec<String>,
}

/// Callback type for progress updates during scanning.
pub type ProgressCallback = Arc<dyn Fn(ScanProgress) + Send + Sync>;

/// Supported languages for analysis.
///
/// These match the engine's Language enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    Rust,
    Go,
    Java,
    TypeScript,
    JavaScript,
}

impl Language {
    /// Get the language string for API requests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::Rust => "rust",
            Language::Go => "go",
            Language::Java => "java",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
        }
    }

    /// Detect language from file extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "py" => Some(Language::Python),
            "rs" => Some(Language::Rust),
            "go" => Some(Language::Go),
            "java" => Some(Language::Java),
            "ts" | "tsx" => Some(Language::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            _ => None,
        }
    }
}

/// Detected framework with confidence score.
#[derive(Debug, Clone)]
pub struct DetectedFramework {
    /// Framework name (e.g., "fastapi", "django", "flask")
    pub name: String,
    /// Confidence score [0.0, 1.0]
    pub confidence: f64,
    /// Signals that led to detection
    pub signals: Vec<String>,
}

/// Information about a scanned workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceInfo {
    /// Workspace root path
    pub root: PathBuf,
    /// Human-readable label (usually directory name)
    pub label: String,
    /// Stable workspace identifier (fingerprint)
    pub workspace_id: Option<String>,
    /// Source used to compute workspace_id
    pub workspace_id_source: Option<WorkspaceIdSource>,
    /// Git remote URL (if available)
    pub git_remote: Option<String>,
    /// Detected languages with file counts
    pub languages: HashMap<Language, usize>,
    /// Detected frameworks
    pub frameworks: Vec<DetectedFramework>,
    /// Source files found (path, language)
    pub source_files: Vec<(PathBuf, Language)>,
    /// Meta files found (pyproject.toml, package.json, etc.)
    pub meta_files: Vec<LocalMetaFileInfo>,
    /// Project layout
    pub layout: ProjectLayout,
    /// Workspace settings loaded from configuration files
    pub settings: Option<LoadedSettings>,
}

/// Local meta file information (used during scanning).
#[derive(Debug, Clone)]
pub struct LocalMetaFileInfo {
    /// Path relative to workspace root
    pub path: PathBuf,
    /// File kind (pyproject, package_json, etc.)
    pub kind: MetaFileKind,
    /// File contents
    pub contents: String,
}

/// Known kinds of meta files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaFileKind {
    Pyproject,
    RequirementsTxt,
    SetupPy,
    PackageJson,
    GoMod,
    CargoToml,
    PomXml,
    BuildGradle,
    Other,
}

impl MetaFileKind {
    /// Get the kind string for API requests.
    pub fn as_str(&self) -> &'static str {
        match self {
            MetaFileKind::Pyproject => "pyproject",
            MetaFileKind::RequirementsTxt => "requirements_txt",
            MetaFileKind::SetupPy => "setup_py",
            MetaFileKind::PackageJson => "package_json",
            MetaFileKind::GoMod => "go_mod",
            MetaFileKind::CargoToml => "cargo_toml",
            MetaFileKind::PomXml => "pom_xml",
            MetaFileKind::BuildGradle => "build_gradle",
            MetaFileKind::Other => "other",
        }
    }

    /// Get the language/format string for API requests.
    pub fn language(&self) -> &'static str {
        match self {
            MetaFileKind::Pyproject | MetaFileKind::CargoToml => "toml",
            MetaFileKind::RequirementsTxt => "text",
            MetaFileKind::SetupPy => "python",
            MetaFileKind::PackageJson => "json",
            MetaFileKind::GoMod => "go",
            MetaFileKind::PomXml => "xml",
            MetaFileKind::BuildGradle => "groovy",
            MetaFileKind::Other => "text",
        }
    }

    /// Detect meta file kind from filename.
    pub fn from_filename(filename: &str) -> Option<Self> {
        match filename {
            "pyproject.toml" => Some(MetaFileKind::Pyproject),
            "requirements.txt" => Some(MetaFileKind::RequirementsTxt),
            "setup.py" => Some(MetaFileKind::SetupPy),
            "package.json" => Some(MetaFileKind::PackageJson),
            "go.mod" => Some(MetaFileKind::GoMod),
            "Cargo.toml" => Some(MetaFileKind::CargoToml),
            "pom.xml" => Some(MetaFileKind::PomXml),
            "build.gradle" | "build.gradle.kts" => Some(MetaFileKind::BuildGradle),
            _ => None,
        }
    }
}

impl WorkspaceInfo {
    /// Convert to a WorkspaceDescriptor for the API.
    pub fn to_workspace_descriptor(&self) -> WorkspaceDescriptor {
        WorkspaceDescriptor {
            id: self.workspace_id.clone(),
            id_source: self
                .workspace_id_source
                .as_ref()
                .map(|s| s.as_str().to_string()),
            label: self.label.clone(),
            git_remote: self.git_remote.clone(),
            profiles: self.build_profiles(),
            meta_files: self
                .meta_files
                .iter()
                .map(|mf| MetaFile {
                    path: mf.path.to_string_lossy().to_string(),
                    language: mf.kind.language().to_string(),
                    kind: mf.kind.as_str().to_string(),
                    contents: mf.contents.clone(),
                })
                .collect(),
        }
    }

    /// Get the workspace settings if available.
    pub fn workspace_settings(&self) -> Option<&WorkspaceSettings> {
        self.settings.as_ref().map(|s| &s.settings)
    }

    /// Build advertised profiles based on detected languages and frameworks.
    ///
    /// If workspace settings specify a profile override, that profile is used
    /// with high confidence (1.0) as the first entry.
    fn build_profiles(&self) -> Vec<AdvertisedProfile> {
        let mut profiles = Vec::new();

        // If workspace settings specify a profile, use it as the primary
        if let Some(ref loaded_settings) = self.settings {
            if let Some(ref profile_override) = loaded_settings.settings.profile {
                profiles.push(AdvertisedProfile {
                    id: profile_override.clone(),
                    confidence: 1.0, // Highest confidence for explicit override
                });
            }
        }

        // Add framework-specific profiles (lower confidence if override exists)
        let framework_confidence_factor = if profiles.is_empty() { 1.0 } else { 0.8 };

        for framework in &self.frameworks {
            let profile_id = match framework.name.as_str() {
                "fastapi" => "python_fastapi_backend",
                "flask" => "python_flask_backend",
                "django" => "python_django_backend",
                "express" => "typescript_express_backend",
                "gin" => "go_gin_service",
                "echo" | "fiber" => "go_generic_service",
                "spring" | "springboot" => "java_spring_backend",
                "axum" => "rust_axum_service",
                "actix" => "rust_actix_service",
                "rocket" | "warp" => "rust_generic",
                _ => continue,
            };

            // Skip if this profile was already added via settings override
            if profiles.iter().any(|p| p.id == profile_id) {
                continue;
            }

            profiles.push(AdvertisedProfile {
                id: profile_id.to_string(),
                confidence: framework.confidence * framework_confidence_factor,
            });
        }

        // Add generic language profiles for languages without framework detection
        for (language, _count) in &self.languages {
            let has_framework_profile = profiles.iter().any(|p| {
                p.id.starts_with(match language {
                    Language::Python => "python_",
                    Language::Rust => "rust_",
                    Language::Go => "go_",
                    Language::Java => "java_",
                    Language::TypeScript | Language::JavaScript => "typescript_",
                })
            });

            if !has_framework_profile {
                let profile_id = match language {
                    Language::Python => "python_generic_backend",
                    Language::Rust => "rust_axum_service", // Default to axum as generic Rust profile
                    Language::Go => "go_generic_service",
                    Language::Java => "java_generic",
                    Language::TypeScript | Language::JavaScript => "typescript_express_backend",
                };

                profiles.push(AdvertisedProfile {
                    id: profile_id.to_string(),
                    confidence: 0.7 * framework_confidence_factor,
                });
            }
        }

        // Default profile if nothing detected
        if profiles.is_empty() {
            profiles.push(AdvertisedProfile {
                id: "generic".to_string(),
                confidence: 0.5,
            });
        }

        profiles
    }

    /// Get detected language strings for API requests.
    pub fn language_strings(&self) -> Vec<String> {
        self.languages
            .keys()
            .map(|l| l.as_str().to_string())
            .collect()
    }

    /// Get detected framework strings for API requests.
    pub fn framework_strings(&self) -> Vec<String> {
        self.frameworks.iter().map(|f| f.name.clone()).collect()
    }
}

/// Scanned file information for parallel processing.
#[derive(Debug, Clone)]
struct ScannedFile {
    path: PathBuf,
    language: Language,
}

/// Scanned directory information.
#[derive(Debug, Clone)]
struct ScannedDir {
    relative_path: String,
    is_src: bool,
    is_test: bool,
}

/// Scanner for analyzing workspace structure and detecting project type.
/// Uses the `ignore` crate for parallel directory traversal with built-in gitignore support.
pub struct WorkspaceScanner {
    root: PathBuf,
    progress_callback: Option<ProgressCallback>,
}

impl WorkspaceScanner {
    /// Create a new workspace scanner.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory of the workspace to scan
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            progress_callback: None,
        }
    }

    /// Set a progress callback to receive updates during scanning.
    ///
    /// The callback will be invoked periodically as files are discovered.
    pub fn with_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(ScanProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Scan the workspace and return information about it.
    /// Uses parallel directory traversal for improved performance.
    ///
    /// # Returns
    ///
    /// * `Ok(WorkspaceInfo)` - Workspace information
    /// * `Err(_)` - Failed to scan workspace
    pub fn scan(&mut self) -> Result<WorkspaceInfo> {
        let label = self
            .root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("workspace")
            .to_string();

        // Phase 1: Parallel directory walk to collect file paths
        // Uses ignore crate for built-in gitignore support and parallel traversal
        let walker = WalkBuilder::new(&self.root)
            .hidden(true) // Respect hidden files based on gitignore
            .git_ignore(true) // Respect .gitignore (when .git exists)
            .git_global(true) // Respect global gitignore
            .git_exclude(true) // Respect .git/info/exclude
            .ignore(true) // Respect .ignore files
            .require_git(false) // Don't require .git directory for gitignore support
            .add_custom_ignore_filename(".gitignore") // Always read .gitignore even without .git
            .add_custom_ignore_filename(".dockerignore") // Also respect .dockerignore
            .filter_entry(|entry| {
                // Additional filtering for common non-source directories
                if let Some(name) = entry.file_name().to_str() {
                    !Self::should_skip_directory(name)
                } else {
                    true
                }
            })
            .build();

        // Collect all entries first (parallelization happens in processing)
        let entries: Vec<_> = walker.filter_map(|e| e.ok()).collect();

        // Separate files and directories
        let (files, dirs): (Vec<_>, Vec<_>) = entries
            .iter()
            .filter(|e| e.path() != self.root)
            .partition(|e| e.file_type().is_some_and(|ft| ft.is_file()));

        // Phase 2: Parallel file processing
        // Atomic counters for progress tracking (lock-free)
        let file_count = AtomicUsize::new(0);
        let has_fastapi = AtomicBool::new(false);
        let has_flask = AtomicBool::new(false);
        let has_django = AtomicBool::new(false);
        let has_express = AtomicBool::new(false);
        let has_gin = AtomicBool::new(false);

        // Progress callback reference
        let progress_callback = &self.progress_callback;
        let last_progress_count = AtomicUsize::new(0);

        // Parallel file processing - collect source files and meta files
        let file_results: Vec<_> = files
            .par_iter()
            .filter_map(|entry| {
                let path = entry.path();
                let filename = path.file_name()?.to_str()?;

                // Check for meta files first
                let meta_file = if let Some(kind) = MetaFileKind::from_filename(filename) {
                    fs::read_to_string(path).ok().map(|contents| {
                        let relative_path =
                            path.strip_prefix(&self.root).unwrap_or(path).to_path_buf();
                        LocalMetaFileInfo {
                            path: relative_path,
                            kind,
                            contents,
                        }
                    })
                } else {
                    None
                };

                // Check for source files
                let source_file = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .and_then(Language::from_extension)
                    .map(|language| {
                        // Framework detection - only read file if not already detected
                        match language {
                            Language::Python => {
                                if !has_fastapi.load(Ordering::Relaxed)
                                    || !has_flask.load(Ordering::Relaxed)
                                    || !has_django.load(Ordering::Relaxed)
                                {
                                    if let Ok(contents) = fs::read_to_string(path) {
                                        if contents.contains("from fastapi")
                                            || contents.contains("import fastapi")
                                        {
                                            has_fastapi.store(true, Ordering::Relaxed);
                                        }
                                        if contents.contains("from flask")
                                            || contents.contains("import flask")
                                        {
                                            has_flask.store(true, Ordering::Relaxed);
                                        }
                                        if contents.contains("from django")
                                            || contents.contains("import django")
                                        {
                                            has_django.store(true, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Language::JavaScript | Language::TypeScript => {
                                if !has_express.load(Ordering::Relaxed) {
                                    if let Ok(contents) = fs::read_to_string(path) {
                                        if contents.contains("require('express')")
                                            || contents.contains("require(\"express\")")
                                            || contents.contains("from 'express'")
                                            || contents.contains("from \"express\"")
                                        {
                                            has_express.store(true, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Language::Go => {
                                if !has_gin.load(Ordering::Relaxed) {
                                    if let Ok(contents) = fs::read_to_string(path) {
                                        if contents.contains("github.com/gin-gonic/gin")
                                            || contents.contains("gin.Context")
                                            || contents.contains("gin.Engine")
                                        {
                                            has_gin.store(true, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }

                        // Update progress counter
                        let count = file_count.fetch_add(1, Ordering::Relaxed) + 1;

                        // Emit progress callback (every 50 files)
                        if let Some(callback) = progress_callback {
                            let last = last_progress_count.load(Ordering::Relaxed);
                            if count >= last + 50 || count == 1 {
                                last_progress_count.store(count, Ordering::Relaxed);
                                callback(ScanProgress {
                                    file_count: count,
                                    languages: vec![], // Will be computed at the end
                                    frameworks: Self::build_frameworks_list(
                                        has_fastapi.load(Ordering::Relaxed),
                                        has_flask.load(Ordering::Relaxed),
                                        has_django.load(Ordering::Relaxed),
                                        has_express.load(Ordering::Relaxed),
                                        has_gin.load(Ordering::Relaxed),
                                    ),
                                });
                            }
                        }

                        ScannedFile {
                            path: path.to_path_buf(),
                            language,
                        }
                    });

                Some((source_file, meta_file))
            })
            .collect();

        // Phase 3: Process directories (sequential, as it's fast)
        let dir_results: Vec<ScannedDir> = dirs
            .iter()
            .filter_map(|entry| {
                let path = entry.path();
                let dir_name = path.file_name()?.to_str()?;
                let relative = path
                    .strip_prefix(&self.root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();

                Some(ScannedDir {
                    relative_path: relative,
                    is_src: dir_name == "src" || dir_name == "lib" || dir_name == "app",
                    is_test: dir_name == "tests" || dir_name == "test" || dir_name == "spec",
                })
            })
            .collect();

        // Phase 4: Aggregate results (sequential merge)
        let mut source_files = Vec::new();
        let mut meta_files = Vec::new();
        let mut language_counts: HashMap<Language, usize> = HashMap::new();

        for (source_file, meta_file) in file_results {
            if let Some(sf) = source_file {
                *language_counts.entry(sf.language).or_insert(0) += 1;
                source_files.push((sf.path, sf.language));
            }
            if let Some(mf) = meta_file {
                meta_files.push(mf);
            }
        }

        let mut src_dirs = Vec::new();
        let mut test_dirs = Vec::new();
        let mut all_dirs = Vec::new();

        for dir in dir_results {
            all_dirs.push(dir.relative_path.clone());
            if dir.is_src {
                src_dirs.push(dir.relative_path.clone());
            }
            if dir.is_test {
                test_dirs.push(dir.relative_path);
            }
        }

        // Build detected frameworks
        let mut frameworks = Vec::new();
        if has_fastapi.load(Ordering::Relaxed) {
            frameworks.push(DetectedFramework {
                name: "fastapi".to_string(),
                confidence: 0.9,
                signals: vec!["import fastapi".to_string()],
            });
        }
        if has_flask.load(Ordering::Relaxed) {
            frameworks.push(DetectedFramework {
                name: "flask".to_string(),
                confidence: 0.9,
                signals: vec!["import flask".to_string()],
            });
        }
        if has_django.load(Ordering::Relaxed) {
            frameworks.push(DetectedFramework {
                name: "django".to_string(),
                confidence: 0.9,
                signals: vec!["import django".to_string()],
            });
        }
        if has_express.load(Ordering::Relaxed) {
            frameworks.push(DetectedFramework {
                name: "express".to_string(),
                confidence: 0.9,
                signals: vec!["require('express')".to_string()],
            });
        }
        if has_gin.load(Ordering::Relaxed) {
            frameworks.push(DetectedFramework {
                name: "gin".to_string(),
                confidence: 0.9,
                signals: vec!["github.com/gin-gonic/gin".to_string()],
            });
        }

        let layout = ProjectLayout {
            src_dirs,
            test_dirs,
            other_dirs: vec![],
            directories: all_dirs,
        };

        // Load workspace settings from configuration files
        let settings = load_settings(&self.root);

        // Get git remote for workspace_id computation
        let git_remote = get_git_remote(&self.root);

        // Convert meta_files to workspace_id format for computation
        let workspace_id_meta: Vec<WorkspaceIdMetaFile> = meta_files
            .iter()
            .map(|mf| WorkspaceIdMetaFile {
                kind: mf.kind.as_str(),
                contents: mf.contents.clone(),
            })
            .collect();

        // Compute workspace_id (with persistent mapping)
        let (workspace_id, workspace_id_source) = if let Some(result) = get_or_compute_workspace_id(
            &self.root,
            git_remote.as_deref(),
            Some(&workspace_id_meta),
            Some(&label),
        ) {
            (Some(result.id), Some(result.source))
        } else {
            (None, None)
        };

        // Final progress update
        if let Some(ref callback) = self.progress_callback {
            callback(ScanProgress {
                file_count: source_files.len(),
                languages: language_counts
                    .keys()
                    .map(|l| l.as_str().to_string())
                    .collect(),
                frameworks: Self::build_frameworks_list(
                    has_fastapi.load(Ordering::Relaxed),
                    has_flask.load(Ordering::Relaxed),
                    has_django.load(Ordering::Relaxed),
                    has_express.load(Ordering::Relaxed),
                    has_gin.load(Ordering::Relaxed),
                ),
            });
        }

        Ok(WorkspaceInfo {
            root: self.root.clone(),
            label,
            workspace_id,
            workspace_id_source,
            git_remote,
            languages: language_counts,
            frameworks,
            source_files,
            meta_files,
            layout,
            settings,
        })
    }

    /// Build frameworks list from detection flags.
    fn build_frameworks_list(
        has_fastapi: bool,
        has_flask: bool,
        has_django: bool,
        has_express: bool,
        has_gin: bool,
    ) -> Vec<String> {
        let mut frameworks = Vec::new();
        if has_fastapi {
            frameworks.push("fastapi".to_string());
        }
        if has_flask {
            frameworks.push("flask".to_string());
        }
        if has_django {
            frameworks.push("django".to_string());
        }
        if has_express {
            frameworks.push("express".to_string());
        }
        if has_gin {
            frameworks.push("gin".to_string());
        }
        frameworks
    }

    /// Check if a directory should be skipped during scanning.
    fn should_skip_directory(name: &str) -> bool {
        // Note: .git, hidden dirs are handled by ignore crate's hidden() and git_ignore()
        name == "node_modules"
            || name == "__pycache__"
            || name == "target"
            || name == "venv"
            || name == "env"
            || name == ".venv"
            || name == ".env"
            || name == "dist"
            || name == "build"
            || name == "vendor"
            || name == "site-packages"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_language_from_extension() {
        assert_eq!(Language::from_extension("py"), Some(Language::Python));
        assert_eq!(Language::from_extension("rs"), Some(Language::Rust));
        assert_eq!(Language::from_extension("go"), Some(Language::Go));
        assert_eq!(Language::from_extension("java"), Some(Language::Java));
        assert_eq!(Language::from_extension("ts"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension("tsx"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension("js"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension("jsx"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension("txt"), None);
    }

    #[test]
    fn test_language_as_str() {
        assert_eq!(Language::Python.as_str(), "python");
        assert_eq!(Language::Rust.as_str(), "rust");
        assert_eq!(Language::Go.as_str(), "go");
        assert_eq!(Language::Java.as_str(), "java");
        assert_eq!(Language::TypeScript.as_str(), "typescript");
        assert_eq!(Language::JavaScript.as_str(), "javascript");
    }

    #[test]
    fn test_meta_file_kind_from_filename() {
        assert_eq!(
            MetaFileKind::from_filename("pyproject.toml"),
            Some(MetaFileKind::Pyproject)
        );
        assert_eq!(
            MetaFileKind::from_filename("requirements.txt"),
            Some(MetaFileKind::RequirementsTxt)
        );
        assert_eq!(
            MetaFileKind::from_filename("package.json"),
            Some(MetaFileKind::PackageJson)
        );
        assert_eq!(
            MetaFileKind::from_filename("Cargo.toml"),
            Some(MetaFileKind::CargoToml)
        );
        assert_eq!(MetaFileKind::from_filename("random.txt"), None);
    }

    #[test]
    fn test_scan_empty_workspace() {
        let temp_dir = TempDir::new().unwrap();
        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.source_files.is_empty());
        assert!(info.languages.is_empty());
        assert!(info.frameworks.is_empty());
    }

    #[test]
    fn test_scan_python_workspace() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("main.py");
        fs::write(&file_path, "print('hello')").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert_eq!(info.source_files.len(), 1);
        assert_eq!(info.languages.get(&Language::Python), Some(&1));
    }

    #[test]
    fn test_scan_fastapi_detection() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("app.py");
        fs::write(&file_path, "from fastapi import FastAPI\napp = FastAPI()").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.frameworks.iter().any(|f| f.name == "fastapi"));
    }

    #[test]
    fn test_scan_flask_detection() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("app.py");
        fs::write(&file_path, "from flask import Flask\napp = Flask(__name__)").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.frameworks.iter().any(|f| f.name == "flask"));
    }

    #[test]
    fn test_scan_django_detection() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("settings.py");
        fs::write(&file_path, "from django.conf import settings").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.frameworks.iter().any(|f| f.name == "django"));
    }

    #[test]
    fn test_scan_skips_hidden_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let hidden_dir = temp_dir.path().join(".hidden");
        fs::create_dir(&hidden_dir).unwrap();
        let file_path = hidden_dir.join("secret.py");
        fs::write(&file_path, "secret = 'password'").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.source_files.is_empty());
    }

    #[test]
    fn test_scan_skips_node_modules() {
        let temp_dir = TempDir::new().unwrap();
        let node_modules = temp_dir.path().join("node_modules");
        fs::create_dir(&node_modules).unwrap();
        let file_path = node_modules.join("package.js");
        fs::write(&file_path, "module.exports = {}").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.source_files.is_empty());
    }

    #[test]
    fn test_scan_meta_files() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject = temp_dir.path().join("pyproject.toml");
        fs::write(&pyproject, "[tool.poetry]\nname = \"test\"").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert_eq!(info.meta_files.len(), 1);
        assert_eq!(info.meta_files[0].kind, MetaFileKind::Pyproject);
    }

    #[test]
    fn test_scan_project_layout() {
        let temp_dir = TempDir::new().unwrap();
        let src_dir = temp_dir.path().join("src");
        let tests_dir = temp_dir.path().join("tests");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&tests_dir).unwrap();
        fs::write(src_dir.join("main.py"), "pass").unwrap();
        fs::write(tests_dir.join("test_main.py"), "pass").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.layout.src_dirs.contains(&"src".to_string()));
        assert!(info.layout.test_dirs.contains(&"tests".to_string()));
    }

    #[test]
    fn test_workspace_info_to_descriptor() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("app.py");
        fs::write(&file_path, "from fastapi import FastAPI").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();
        let descriptor = info.to_workspace_descriptor();

        assert!(!descriptor.label.is_empty());
        assert!(!descriptor.profiles.is_empty());
        assert!(
            descriptor
                .profiles
                .iter()
                .any(|p| p.id == "python_fastapi_backend")
        );
    }

    #[test]
    fn test_build_profiles_generic_fallback() {
        let temp_dir = TempDir::new().unwrap();
        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();
        let descriptor = info.to_workspace_descriptor();

        assert_eq!(descriptor.profiles.len(), 1);
        assert_eq!(descriptor.profiles[0].id, "generic");
    }

    #[test]
    fn test_build_profiles_python_generic() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("main.py");
        fs::write(&file_path, "print('hello')").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();
        let descriptor = info.to_workspace_descriptor();

        assert!(
            descriptor
                .profiles
                .iter()
                .any(|p| p.id == "python_generic_backend")
        );
    }

    #[test]
    fn test_language_strings() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("main.py"), "pass").unwrap();
        fs::write(temp_dir.path().join("main.rs"), "fn main() {}").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();
        let languages = info.language_strings();

        assert!(languages.contains(&"python".to_string()));
        assert!(languages.contains(&"rust".to_string()));
    }

    #[test]
    fn test_framework_strings() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("app.py"),
            "from fastapi import FastAPI",
        )
        .unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();
        let frameworks = info.framework_strings();

        assert!(frameworks.contains(&"fastapi".to_string()));
    }

    #[test]
    fn test_gitignore_respected() {
        let temp_dir = TempDir::new().unwrap();
        let gitignore_path = temp_dir.path().join(".gitignore");
        fs::write(&gitignore_path, "*.log\nsecret.py").unwrap();

        // Create files that should be ignored
        fs::write(temp_dir.path().join("app.log"), "log content").unwrap();
        fs::write(temp_dir.path().join("secret.py"), "secret = 'password'").unwrap();

        // Create files that should NOT be ignored
        fs::write(temp_dir.path().join("main.py"), "print('hello')").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        // Should only find main.py, not the ignored files
        assert_eq!(info.source_files.len(), 1);
        assert!(
            info.source_files
                .iter()
                .any(|(p, _)| p.ends_with("main.py"))
        );
        assert!(
            info.source_files
                .iter()
                .all(|(p, _)| !p.ends_with("app.log"))
        );
        assert!(
            info.source_files
                .iter()
                .all(|(p, _)| !p.ends_with("secret.py"))
        );
    }

    #[test]
    fn test_dockerignore_respected() {
        let temp_dir = TempDir::new().unwrap();
        let dockerignore_path = temp_dir.path().join(".dockerignore");
        fs::write(&dockerignore_path, "node_modules/\n*.tmp").unwrap();

        // Create directories and files that should be ignored
        let node_modules = temp_dir.path().join("node_modules");
        fs::create_dir(&node_modules).unwrap();
        fs::write(node_modules.join("package.json"), "{}").unwrap();

        fs::write(temp_dir.path().join("temp.tmp"), "temp content").unwrap();

        // Create files that should NOT be ignored
        fs::write(temp_dir.path().join("main.py"), "print('hello')").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        // Should only find main.py, not the ignored files/dirs
        assert_eq!(info.source_files.len(), 1);
        assert!(
            info.source_files
                .iter()
                .any(|(p, _)| p.ends_with("main.py"))
        );
        assert!(
            info.source_files
                .iter()
                .all(|(p, _)| !p.ends_with("temp.tmp"))
        );
    }
}

//! Workspace and node identifier computation.
//!
//! This module provides functions to compute stable identifiers:
//!
//! ## Workspace IDs (`wks_*`)
//! Fingerprint computed from stable workspace characteristics:
//! 1. Git remote URL (most reliable)
//! 2. Project manifest name (fallback)
//! 3. Workspace label scoped to org (last resort)
//!
//! ## File IDs (`uf:file:v1:*`)
//! Stable, globally unique identifier for files. Computed from:
//! - Git remote + relative path (if git remote available)
//! - Workspace ID + relative path (fallback, localized to workspace)
//!
//! ## Symbol IDs (`uf:sym:v1:*`)
//! Stable, globally unique identifier for functions/classes. Computed from:
//! - File ID + qualified name

use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

/// Source used to compute workspace_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIdSource {
    /// Computed from git remote URL - most stable.
    Git,
    /// Computed from project manifest (pyproject.toml, package.json, etc.).
    Manifest,
    /// Computed from workspace label - least stable.
    Label,
}

impl WorkspaceIdSource {
    /// Get the string representation for API requests.
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkspaceIdSource::Git => "git",
            WorkspaceIdSource::Manifest => "manifest",
            WorkspaceIdSource::Label => "label",
        }
    }
}

/// Result of workspace ID computation.
#[derive(Debug, Clone)]
pub struct WorkspaceIdResult {
    /// The computed workspace ID (format: wks_{16_hex_chars}).
    pub id: String,
    /// The source used to compute the ID.
    pub source: WorkspaceIdSource,
}

/// Normalize a git remote URL to a canonical form.
///
/// Handles various git URL formats and normalizes them to a consistent form:
/// - `git@github.com:org/repo.git` -> `github.com/org/repo`
/// - `https://github.com/org/repo.git` -> `github.com/org/repo`
/// - `ssh://git@github.com/org/repo` -> `github.com/org/repo`
pub fn normalize_git_remote(remote: &str) -> String {
    let mut remote = remote.trim().to_string();

    // Handle SSH format: git@github.com:org/repo.git
    if remote.starts_with("git@") {
        remote = remote[4..].to_string();
        remote = remote.replacen(":", "/", 1);
    }
    // Handle explicit SSH protocol: ssh://git@github.com/org/repo
    else if remote.starts_with("ssh://") {
        remote = remote[6..].to_string();
        if remote.starts_with("git@") {
            remote = remote[4..].to_string();
        }
    }
    // Handle HTTP(S) protocol
    else if let Some(pos) = remote.find("://") {
        remote = remote[(pos + 3)..].to_string();
        // Remove credentials if present (user:pass@host)
        if let Some(at_pos) = remote.find('@') {
            if at_pos < remote.find('/').unwrap_or(remote.len()) {
                remote = remote[(at_pos + 1)..].to_string();
            }
        }
    }

    // Remove .git suffix
    if remote.ends_with(".git") {
        remote = remote[..remote.len() - 4].to_string();
    }

    // Remove trailing slashes
    remote = remote.trim_end_matches('/').to_string();

    // Lowercase for consistency
    remote.to_lowercase()
}

/// Compute SHA256 hash and return first 16 hex chars.
fn compute_hash(source: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8]) // 8 bytes = 16 hex chars
}

/// Compute SHA256 hash and return first 24 hex chars (for file/symbol IDs).
fn compute_hash_24(source: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..12]) // 12 bytes = 24 hex chars
}

/// Normalize a relative file path to canonical form.
///
/// This ensures consistent path representation across different platforms
/// and client implementations.
///
/// Rules:
/// 1. Convert `\` to `/`
/// 2. Strip leading `./`
/// 3. Collapse `//` to `/`
/// 4. Resolve `.` and `..` segments syntactically
/// 5. Strip leading `/` (must be relative)
/// 6. No trailing `/`
/// 7. Case-sensitive (matches git behavior)
///
/// # Examples
///
/// ```
/// use unfault::session::normalize_rel_path;
///
/// assert_eq!(normalize_rel_path("src/main.py"), "src/main.py");
/// assert_eq!(normalize_rel_path("./src/main.py"), "src/main.py");
/// assert_eq!(normalize_rel_path("src//main.py"), "src/main.py");
/// assert_eq!(normalize_rel_path("src/foo/../main.py"), "src/main.py");
/// assert_eq!(normalize_rel_path("\\src\\main.py"), "src/main.py");
/// ```
pub fn normalize_rel_path(path: &str) -> String {
    // Step 1: Convert backslashes to forward slashes
    let mut path = path.replace('\\', "/");

    // Step 2: Strip leading ./
    while path.starts_with("./") {
        path = path[2..].to_string();
    }

    // Step 3: Collapse // to /
    while path.contains("//") {
        path = path.replace("//", "/");
    }

    // Step 4: Resolve . and .. segments syntactically
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                // Only pop if we have segments and the last one isn't ".."
                if !segments.is_empty() && segments.last() != Some(&"..") {
                    segments.pop();
                }
                // If we can't go up, we silently drop the ".." to avoid
                // escaping above the workspace root
            }
            s => segments.push(s),
        }
    }

    // Step 5 & 6: Join (no leading or trailing /)
    segments.join("/")
}

/// Compute a stable file identifier.
///
/// Format: `uf:file:v1:{24_hex_chars}`
///
/// The identifier is computed from:
/// - If `git_remote` is available: `sha256(normalized_git_remote + "\0" + normalized_rel_path)`
/// - Otherwise: `sha256(workspace_id + "\0" + normalized_rel_path)` (localized, no cross-workspace linking)
///
/// # Arguments
///
/// * `git_remote` - Git remote URL (e.g., "git@github.com:acme/repo.git")
/// * `workspace_id` - Workspace identifier (e.g., "wks_abc123...")
/// * `rel_path` - File path relative to workspace root
///
/// # Returns
///
/// A stable file ID string in the format `uf:file:v1:{24_hex_chars}`
pub fn compute_file_id(git_remote: Option<&str>, workspace_id: &str, rel_path: &str) -> String {
    let norm_path = normalize_rel_path(rel_path);

    let canonical = if let Some(remote) = git_remote {
        let norm_remote = normalize_git_remote(remote);
        if !norm_remote.is_empty() {
            format!("{}\x00{}", norm_remote, norm_path)
        } else {
            // Git remote normalized to empty, fall back to workspace_id
            format!("{}\x00{}", workspace_id, norm_path)
        }
    } else {
        // No git remote, use workspace_id (localized)
        format!("{}\x00{}", workspace_id, norm_path)
    };

    let hash = compute_hash_24(&canonical);
    format!("uf:file:v1:{}", hash)
}

/// Compute a stable symbol identifier for functions and classes.
///
/// Format: `uf:sym:v1:{24_hex_chars}`
///
/// The identifier is computed from: `sha256(file_id + "\0" + qualified_name)`
///
/// # Arguments
///
/// * `file_id` - The file ID containing this symbol (from `compute_file_id`)
/// * `qualified_name` - Qualified name of the symbol (e.g., "MyClass.my_method")
///
/// # Returns
///
/// A stable symbol ID string in the format `uf:sym:v1:{24_hex_chars}`
pub fn compute_symbol_id(file_id: &str, qualified_name: &str) -> String {
    let canonical = format!("{}\x00{}", file_id, qualified_name);
    let hash = compute_hash_24(&canonical);
    format!("uf:sym:v1:{}", hash)
}

/// Get the git remote URL for a workspace.
///
/// Tries to get the "origin" remote first, falls back to any available remote.
pub fn get_git_remote(workspace_root: &Path) -> Option<String> {
    // Try to get origin remote
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(workspace_root)
        .output()
        .ok()?;

    if output.status.success() {
        let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !remote.is_empty() {
            return Some(remote);
        }
    }

    // Fall back to first available remote
    let output = Command::new("git")
        .args(["remote"])
        .current_dir(workspace_root)
        .output()
        .ok()?;

    if output.status.success() {
        let remotes = String::from_utf8_lossy(&output.stdout);
        if let Some(first_remote) = remotes.lines().next() {
            let remote_output = Command::new("git")
                .args(["remote", "get-url", first_remote])
                .current_dir(workspace_root)
                .output()
                .ok()?;

            if remote_output.status.success() {
                let remote = String::from_utf8_lossy(&remote_output.stdout)
                    .trim()
                    .to_string();
                if !remote.is_empty() {
                    return Some(remote);
                }
            }
        }
    }

    None
}

/// Extract project name from pyproject.toml content.
fn extract_pyproject_name(contents: &str) -> Option<String> {
    // Try [project].name first (PEP 621)
    let project_section_re =
        regex::Regex::new(r#"\[project\]\s*\n[^\[]*?name\s*=\s*["\']([^"\']+)["\']"#).ok()?;
    if let Some(captures) = project_section_re.captures(contents) {
        return Some(captures.get(1)?.as_str().to_string());
    }

    // Try [tool.poetry].name
    let poetry_section_re =
        regex::Regex::new(r#"\[tool\.poetry\]\s*\n[^\[]*?name\s*=\s*["\']([^"\']+)["\']"#).ok()?;
    if let Some(captures) = poetry_section_re.captures(contents) {
        return Some(captures.get(1)?.as_str().to_string());
    }

    None
}

/// Extract project name from package.json content.
fn extract_package_json_name(contents: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(contents).ok()?;
    json.get("name")?.as_str().map(|s| s.to_string())
}

/// Extract package name from Cargo.toml content.
fn extract_cargo_toml_name(contents: &str) -> Option<String> {
    let cargo_section_re =
        regex::Regex::new(r#"\[package\]\s*\n[^\[]*?name\s*=\s*["\']([^"\']+)["\']"#).ok()?;
    if let Some(captures) = cargo_section_re.captures(contents) {
        return Some(captures.get(1)?.as_str().to_string());
    }
    None
}

/// Extract module path from go.mod content.
fn extract_go_mod_module(contents: &str) -> Option<String> {
    let module_re = regex::Regex::new(r#"^module\s+(\S+)"#).ok()?;
    for line in contents.lines() {
        if let Some(captures) = module_re.captures(line) {
            return Some(captures.get(1)?.as_str().to_string());
        }
    }
    None
}

/// Meta file information for project name extraction.
pub struct MetaFileInfo {
    pub kind: &'static str,
    pub contents: String,
}

/// Information about a package exported by a workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageExport {
    /// The package name (e.g., "core_lib", "@acme/core-lib")
    pub package_name: String,
    /// The language/ecosystem
    pub language: &'static str,
    /// Source of the export info: "manifest" or "config"
    pub source: &'static str,
}

/// Extract package export information from manifest files.
///
/// Returns the package name and language for cross-workspace dependency tracking.
pub fn extract_package_export(meta_files: &[MetaFileInfo]) -> Option<PackageExport> {
    for mf in meta_files {
        match mf.kind {
            "pyproject" => {
                if let Some(name) = extract_pyproject_name(&mf.contents) {
                    return Some(PackageExport {
                        package_name: name,
                        language: "python",
                        source: "manifest",
                    });
                }
            }
            "package_json" => {
                if let Some(name) = extract_package_json_name(&mf.contents) {
                    return Some(PackageExport {
                        package_name: name,
                        language: "typescript",
                        source: "manifest",
                    });
                }
            }
            "cargo_toml" => {
                if let Some(name) = extract_cargo_toml_name(&mf.contents) {
                    return Some(PackageExport {
                        package_name: name,
                        language: "rust",
                        source: "manifest",
                    });
                }
            }
            "go_mod" => {
                if let Some(name) = extract_go_mod_module(&mf.contents) {
                    return Some(PackageExport {
                        package_name: name,
                        language: "go",
                        source: "manifest",
                    });
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract project name from meta files.
pub fn extract_project_name_from_meta_files(meta_files: &[MetaFileInfo]) -> Option<String> {
    for mf in meta_files {
        let name = match mf.kind {
            "pyproject" => extract_pyproject_name(&mf.contents),
            "package_json" => extract_package_json_name(&mf.contents),
            "cargo_toml" => extract_cargo_toml_name(&mf.contents),
            "go_mod" => extract_go_mod_module(&mf.contents),
            _ => None,
        };

        if name.is_some() {
            return name;
        }
    }

    None
}

/// Compute a stable workspace identifier.
///
/// Tries sources in order of stability:
/// 1. Git remote URL (if available)
/// 2. Project manifest name (if available)
/// 3. Workspace label (fallback)
pub fn compute_workspace_id(
    git_remote: Option<&str>,
    meta_files: Option<&[MetaFileInfo]>,
    workspace_label: Option<&str>,
) -> Option<WorkspaceIdResult> {
    // Priority 1: Git remote URL
    if let Some(remote) = git_remote {
        let normalized = normalize_git_remote(remote);
        if !normalized.is_empty() {
            let hash = compute_hash(&format!("git:{}", normalized));
            return Some(WorkspaceIdResult {
                id: format!("wks_{}", hash),
                source: WorkspaceIdSource::Git,
            });
        }
    }

    // Priority 2: Project manifest name
    if let Some(files) = meta_files {
        if let Some(project_name) = extract_project_name_from_meta_files(files) {
            let hash = compute_hash(&format!("manifest:{}", project_name));
            return Some(WorkspaceIdResult {
                id: format!("wks_{}", hash),
                source: WorkspaceIdSource::Manifest,
            });
        }
    }

    // Priority 3: Workspace label
    if let Some(label) = workspace_label {
        // Note: In CLI, we don't have org_id, so we use "cli" as scope
        // This means label-based IDs from CLI won't match API-computed ones
        // until git remote is added
        let hash = compute_hash(&format!("label:cli:{}", label));
        return Some(WorkspaceIdResult {
            id: format!("wks_{}", hash),
            source: WorkspaceIdSource::Label,
        });
    }

    None
}

/// Get or compute workspace ID with persistent mapping.
///
/// This function ensures workspace ID stability across git remote changes:
/// 1. First checks if there's an existing mapping in config for this directory
/// 2. If not found, computes the workspace ID using the standard logic
/// 3. Stores the mapping in config for future use
///
/// This prevents workspace ID changes when:
/// - A git remote is added to a previously local-only project
/// - The git remote URL changes
///
/// # Arguments
///
/// * `workspace_path` - The directory path of the workspace
/// * `git_remote` - Optional git remote URL
/// * `meta_files` - Optional manifest files for ID computation
/// * `workspace_label` - Optional fallback label (usually directory name)
///
/// # Returns
///
/// The workspace ID result, either from existing mapping or freshly computed.
/// Returns `None` if no workspace ID could be determined.
pub fn get_or_compute_workspace_id(
    workspace_path: &Path,
    git_remote: Option<&str>,
    meta_files: Option<&[MetaFileInfo]>,
    workspace_label: Option<&str>,
) -> Option<WorkspaceIdResult> {
    use crate::config::Config;

    // Try to load config and check for existing mapping
    if let Ok(config) = Config::load() {
        if let Some(existing_id) = config.get_workspace_mapping(workspace_path) {
            // Found existing mapping - use it regardless of current git remote/manifest
            return Some(WorkspaceIdResult {
                id: existing_id.clone(),
                source: WorkspaceIdSource::Manifest, // Mark as stable source
            });
        }
    }

    // No existing mapping - compute workspace ID
    let result = compute_workspace_id(git_remote, meta_files, workspace_label)?;

    // Store the mapping for future use
    if let Ok(mut config) = Config::load() {
        if config.set_workspace_mapping(workspace_path, result.id.clone()).is_ok() {
            // Ignore save errors - not critical
            let _ = config.save();
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_git_remote_ssh() {
        assert_eq!(
            normalize_git_remote("git@github.com:acme/repo.git"),
            "github.com/acme/repo"
        );
    }

    #[test]
    fn test_normalize_git_remote_https() {
        assert_eq!(
            normalize_git_remote("https://github.com/acme/repo.git"),
            "github.com/acme/repo"
        );
    }

    #[test]
    fn test_normalize_git_remote_ssh_protocol() {
        assert_eq!(
            normalize_git_remote("ssh://git@github.com/acme/repo.git"),
            "github.com/acme/repo"
        );
    }

    #[test]
    fn test_normalize_git_remote_no_suffix() {
        assert_eq!(
            normalize_git_remote("https://github.com/acme/repo"),
            "github.com/acme/repo"
        );
    }

    #[test]
    fn test_normalize_git_remote_trailing_slash() {
        assert_eq!(
            normalize_git_remote("https://github.com/acme/repo/"),
            "github.com/acme/repo"
        );
    }

    #[test]
    fn test_compute_workspace_id_git() {
        let result = compute_workspace_id(
            Some("git@github.com:acme/payments.git"),
            None,
            Some("payments"),
        );

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.id.starts_with("wks_"));
        assert_eq!(result.id.len(), 20); // "wks_" + 16 hex chars
        assert_eq!(result.source, WorkspaceIdSource::Git);
    }

    #[test]
    fn test_compute_workspace_id_manifest() {
        let meta_files = vec![MetaFileInfo {
            kind: "pyproject",
            contents: r#"[project]
name = "payments-service"
version = "1.0.0"
"#
            .to_string(),
        }];

        let result = compute_workspace_id(None, Some(&meta_files), Some("payments"));

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.id.starts_with("wks_"));
        assert_eq!(result.source, WorkspaceIdSource::Manifest);
    }

    #[test]
    fn test_compute_workspace_id_label_fallback() {
        let result = compute_workspace_id(None, None, Some("my-project"));

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.id.starts_with("wks_"));
        assert_eq!(result.source, WorkspaceIdSource::Label);
    }

    #[test]
    fn test_compute_workspace_id_none() {
        let result = compute_workspace_id(None, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_pyproject_name_pep621() {
        let content = r#"[project]
name = "my-package"
version = "1.0.0"
"#;
        assert_eq!(
            extract_pyproject_name(content),
            Some("my-package".to_string())
        );
    }

    #[test]
    fn test_extract_pyproject_name_poetry() {
        let content = r#"[tool.poetry]
name = "my-package"
version = "1.0.0"
"#;
        assert_eq!(
            extract_pyproject_name(content),
            Some("my-package".to_string())
        );
    }

    #[test]
    fn test_extract_package_json_name() {
        let content = r#"{"name": "my-package", "version": "1.0.0"}"#;
        assert_eq!(
            extract_package_json_name(content),
            Some("my-package".to_string())
        );
    }

    #[test]
    fn test_extract_cargo_toml_name() {
        let content = r#"[package]
name = "my-crate"
version = "0.1.0"
"#;
        assert_eq!(
            extract_cargo_toml_name(content),
            Some("my-crate".to_string())
        );
    }

    #[test]
    fn test_extract_go_mod_module() {
        let content = r#"module github.com/acme/myservice

go 1.21
"#;
        assert_eq!(
            extract_go_mod_module(content),
            Some("github.com/acme/myservice".to_string())
        );
    }

    // =========================================================================
    // extract_package_export tests
    // =========================================================================

    #[test]
    fn test_extract_package_export_python() {
        let meta_files = vec![MetaFileInfo {
            kind: "pyproject",
            contents: r#"[project]
name = "core-lib"
version = "1.0.0"
"#
            .to_string(),
        }];

        let export = extract_package_export(&meta_files);
        assert!(export.is_some());
        let export = export.unwrap();
        assert_eq!(export.package_name, "core-lib");
        assert_eq!(export.language, "python");
        assert_eq!(export.source, "manifest");
    }

    #[test]
    fn test_extract_package_export_typescript() {
        let meta_files = vec![MetaFileInfo {
            kind: "package_json",
            contents: r#"{"name": "@acme/core-lib", "version": "1.0.0"}"#.to_string(),
        }];

        let export = extract_package_export(&meta_files);
        assert!(export.is_some());
        let export = export.unwrap();
        assert_eq!(export.package_name, "@acme/core-lib");
        assert_eq!(export.language, "typescript");
        assert_eq!(export.source, "manifest");
    }

    #[test]
    fn test_extract_package_export_rust() {
        let meta_files = vec![MetaFileInfo {
            kind: "cargo_toml",
            contents: r#"[package]
name = "core_lib"
version = "0.1.0"
"#
            .to_string(),
        }];

        let export = extract_package_export(&meta_files);
        assert!(export.is_some());
        let export = export.unwrap();
        assert_eq!(export.package_name, "core_lib");
        assert_eq!(export.language, "rust");
        assert_eq!(export.source, "manifest");
    }

    #[test]
    fn test_extract_package_export_go() {
        let meta_files = vec![MetaFileInfo {
            kind: "go_mod",
            contents: r#"module github.com/acme/core-lib

go 1.21
"#
            .to_string(),
        }];

        let export = extract_package_export(&meta_files);
        assert!(export.is_some());
        let export = export.unwrap();
        assert_eq!(export.package_name, "github.com/acme/core-lib");
        assert_eq!(export.language, "go");
        assert_eq!(export.source, "manifest");
    }

    #[test]
    fn test_extract_package_export_none() {
        let meta_files: Vec<MetaFileInfo> = vec![];
        assert!(extract_package_export(&meta_files).is_none());
    }

    #[test]
    fn test_extract_package_export_priority() {
        // If multiple manifests exist, first match wins
        let meta_files = vec![
            MetaFileInfo {
                kind: "pyproject",
                contents: r#"[project]
name = "python-pkg"
"#
                .to_string(),
            },
            MetaFileInfo {
                kind: "package_json",
                contents: r#"{"name": "npm-pkg"}"#.to_string(),
            },
        ];

        let export = extract_package_export(&meta_files);
        assert!(export.is_some());
        let export = export.unwrap();
        assert_eq!(export.package_name, "python-pkg");
        assert_eq!(export.language, "python");
    }

    // =========================================================================
    // normalize_rel_path tests
    // =========================================================================

    #[test]
    fn test_normalize_rel_path_simple() {
        assert_eq!(normalize_rel_path("src/main.py"), "src/main.py");
    }

    #[test]
    fn test_normalize_rel_path_leading_dot_slash() {
        assert_eq!(normalize_rel_path("./src/main.py"), "src/main.py");
        assert_eq!(normalize_rel_path("././src/main.py"), "src/main.py");
    }

    #[test]
    fn test_normalize_rel_path_backslashes() {
        assert_eq!(normalize_rel_path("src\\main.py"), "src/main.py");
        assert_eq!(normalize_rel_path("src\\foo\\main.py"), "src/foo/main.py");
    }

    #[test]
    fn test_normalize_rel_path_double_slashes() {
        assert_eq!(normalize_rel_path("src//main.py"), "src/main.py");
        assert_eq!(normalize_rel_path("src///foo//main.py"), "src/foo/main.py");
    }

    #[test]
    fn test_normalize_rel_path_dot_segments() {
        assert_eq!(normalize_rel_path("src/./main.py"), "src/main.py");
        assert_eq!(normalize_rel_path("src/foo/../main.py"), "src/main.py");
        assert_eq!(
            normalize_rel_path("src/foo/bar/../../main.py"),
            "src/main.py"
        );
    }

    #[test]
    fn test_normalize_rel_path_leading_slash_stripped() {
        assert_eq!(normalize_rel_path("/src/main.py"), "src/main.py");
    }

    #[test]
    fn test_normalize_rel_path_trailing_slash_stripped() {
        assert_eq!(normalize_rel_path("src/foo/"), "src/foo");
    }

    #[test]
    fn test_normalize_rel_path_escape_above_root_dropped() {
        // Trying to escape above root just drops those segments
        assert_eq!(normalize_rel_path("../src/main.py"), "src/main.py");
        assert_eq!(normalize_rel_path("../../src/main.py"), "src/main.py");
    }

    #[test]
    fn test_normalize_rel_path_complex() {
        assert_eq!(
            normalize_rel_path(".\\src//foo\\..\\bar/./baz.py"),
            "src/bar/baz.py"
        );
    }

    // =========================================================================
    // compute_file_id tests
    // =========================================================================

    #[test]
    fn test_compute_file_id_with_git_remote() {
        let file_id = compute_file_id(
            Some("git@github.com:acme/payments.git"),
            "wks_ignored",
            "src/billing/plans.py",
        );

        assert!(file_id.starts_with("uf:file:v1:"));
        assert_eq!(file_id.len(), 11 + 24); // "uf:file:v1:" + 24 hex chars
    }

    #[test]
    fn test_compute_file_id_without_git_remote() {
        let file_id = compute_file_id(None, "wks_abc123def456", "src/billing/plans.py");

        assert!(file_id.starts_with("uf:file:v1:"));
        assert_eq!(file_id.len(), 11 + 24);
    }

    #[test]
    fn test_compute_file_id_stable_across_git_formats() {
        // Same repo, different URL formats should produce same file_id
        let id1 = compute_file_id(Some("git@github.com:acme/repo.git"), "wks_x", "src/main.py");
        let id2 = compute_file_id(
            Some("https://github.com/acme/repo.git"),
            "wks_x",
            "src/main.py",
        );
        let id3 = compute_file_id(
            Some("ssh://git@github.com/acme/repo.git"),
            "wks_x",
            "src/main.py",
        );

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
    }

    #[test]
    fn test_compute_file_id_stable_across_path_formats() {
        // Same file, different path formats should produce same file_id
        let id1 = compute_file_id(Some("git@github.com:acme/repo.git"), "wks_x", "src/main.py");
        let id2 = compute_file_id(
            Some("git@github.com:acme/repo.git"),
            "wks_x",
            "./src/main.py",
        );
        let id3 = compute_file_id(
            Some("git@github.com:acme/repo.git"),
            "wks_x",
            "src//main.py",
        );
        let id4 = compute_file_id(
            Some("git@github.com:acme/repo.git"),
            "wks_x",
            "src/foo/../main.py",
        );

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(id3, id4);
    }

    #[test]
    fn test_compute_file_id_different_files_different_ids() {
        let id1 = compute_file_id(Some("git@github.com:acme/repo.git"), "wks_x", "src/a.py");
        let id2 = compute_file_id(Some("git@github.com:acme/repo.git"), "wks_x", "src/b.py");

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compute_file_id_different_repos_different_ids() {
        let id1 = compute_file_id(
            Some("git@github.com:acme/repo1.git"),
            "wks_x",
            "src/main.py",
        );
        let id2 = compute_file_id(
            Some("git@github.com:acme/repo2.git"),
            "wks_x",
            "src/main.py",
        );

        assert_ne!(id1, id2);
    }

    // =========================================================================
    // compute_symbol_id tests
    // =========================================================================

    #[test]
    fn test_compute_symbol_id_format() {
        let file_id = "uf:file:v1:a1b2c3d4e5f6a1b2c3d4e5f6";
        let symbol_id = compute_symbol_id(file_id, "MyClass.my_method");

        assert!(symbol_id.starts_with("uf:sym:v1:"));
        assert_eq!(symbol_id.len(), 10 + 24); // "uf:sym:v1:" + 24 hex chars
    }

    #[test]
    fn test_compute_symbol_id_different_symbols_different_ids() {
        let file_id = "uf:file:v1:a1b2c3d4e5f6a1b2c3d4e5f6";

        let id1 = compute_symbol_id(file_id, "func_a");
        let id2 = compute_symbol_id(file_id, "func_b");

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compute_symbol_id_same_name_different_files() {
        let file_id1 = "uf:file:v1:aaaaaaaaaaaaaaaaaaaaaaaa";
        let file_id2 = "uf:file:v1:bbbbbbbbbbbbbbbbbbbbbbbb";

        let id1 = compute_symbol_id(file_id1, "process");
        let id2 = compute_symbol_id(file_id2, "process");

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compute_symbol_id_stable() {
        let file_id = "uf:file:v1:a1b2c3d4e5f6a1b2c3d4e5f6";

        let id1 = compute_symbol_id(file_id, "MyClass.my_method");
        let id2 = compute_symbol_id(file_id, "MyClass.my_method");

        assert_eq!(id1, id2);
    }
}

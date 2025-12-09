//! Workspace identifier computation.
//!
//! This module provides functions to compute stable workspace identifiers
//! that remain consistent across CLI and LSP analysis sessions.
//!
//! The workspace_id is a fingerprint computed from stable workspace characteristics:
//! 1. Git remote URL (most reliable)
//! 2. Project manifest name (fallback)
//! 3. Workspace label scoped to org (last resort)

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
    let project_section_re = regex::Regex::new(r#"\[project\]\s*\n[^\[]*?name\s*=\s*["\']([^"\']+)["\']"#).ok()?;
    if let Some(captures) = project_section_re.captures(contents) {
        return Some(captures.get(1)?.as_str().to_string());
    }

    // Try [tool.poetry].name
    let poetry_section_re = regex::Regex::new(r#"\[tool\.poetry\]\s*\n[^\[]*?name\s*=\s*["\']([^"\']+)["\']"#).ok()?;
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
    let cargo_section_re = regex::Regex::new(r#"\[package\]\s*\n[^\[]*?name\s*=\s*["\']([^"\']+)["\']"#).ok()?;
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
}
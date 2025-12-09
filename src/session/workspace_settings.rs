//! # Workspace Settings
//!
//! This module handles parsing workspace-level configuration for Unfault analysis.
//! Configuration can be read from various project manifest files:
//!
//! - `pyproject.toml` → `[tool.unfault]`
//! - `Cargo.toml` → `[package.metadata.unfault]`
//! - `package.json` → `"unfault": {...}`
//! - `unfault.toml` → Root level (standalone fallback)
//!
//! ## Priority
//!
//! Manifest file configuration takes precedence over standalone `unfault.toml`.
//! Only one source is used per project (no merging).

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Workspace-level configuration for Unfault analysis.
///
/// These settings control which profile, rules, and dimensions are used
/// during analysis. Settings are read from the project's manifest file
/// or a standalone `unfault.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WorkspaceSettings {
    /// Override the auto-detected profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// Limit analysis to specific dimensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<Vec<String>>,

    /// Rule-specific configuration.
    #[serde(default)]
    pub rules: RuleSettings,
}

/// Rule-specific settings.
///
/// Controls which rules are included/excluded and their severity levels.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuleSettings {
    /// Rules to exclude (supports glob patterns like `python.http.*`).
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Additional rules to include beyond the profile defaults.
    #[serde(default)]
    pub include: Vec<String>,

    /// Severity overrides (rule_id → severity).
    #[serde(default)]
    pub severity: HashMap<String, String>,
}

impl WorkspaceSettings {
    /// Create empty settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any settings are configured.
    pub fn is_empty(&self) -> bool {
        self.profile.is_none()
            && self.dimensions.is_none()
            && self.rules.exclude.is_empty()
            && self.rules.include.is_empty()
            && self.rules.severity.is_empty()
    }

    /// Check if a rule ID matches any exclusion pattern.
    ///
    /// Supports glob patterns:
    /// - `python.http.missing_timeout` - Exact match
    /// - `python.http.*` - Matches any rule in `python.http` namespace
    /// - `*.missing_timeout` - Matches this rule in any language
    /// - `python.**` - Matches all rules starting with `python.`
    pub fn is_rule_excluded(&self, rule_id: &str) -> bool {
        self.rules
            .exclude
            .iter()
            .any(|pattern| glob_match(pattern, rule_id))
    }

    /// Check if a rule ID matches any inclusion pattern.
    pub fn is_rule_included(&self, rule_id: &str) -> bool {
        self.rules
            .include
            .iter()
            .any(|pattern| glob_match(pattern, rule_id))
    }

    /// Get severity override for a rule, if any.
    pub fn get_severity_override(&self, rule_id: &str) -> Option<&str> {
        self.rules.severity.get(rule_id).map(|s| s.as_str())
    }

    /// Filter a list of rule IDs based on exclusions and inclusions.
    ///
    /// Returns a new list with:
    /// - Excluded rules removed
    /// - Included rules added (from the `all_available_rules` set)
    pub fn filter_rules(
        &self,
        profile_rules: &[String],
        all_available_rules: &[String],
    ) -> Vec<String> {
        let mut result: Vec<String> = profile_rules
            .iter()
            .filter(|rule_id| !self.is_rule_excluded(rule_id))
            .cloned()
            .collect();

        // Add included rules that aren't already in the list
        for rule_id in all_available_rules {
            if self.is_rule_included(rule_id) && !result.contains(rule_id) {
                result.push(rule_id.clone());
            }
        }

        result
    }
}

/// Simple glob matching for rule patterns.
///
/// Supports:
/// - `*` matches any sequence of characters within a segment (not `.`)
/// - `**` matches any sequence including `.`
/// - Exact matches
fn glob_match(pattern: &str, rule_id: &str) -> bool {
    // Exact match
    if pattern == rule_id {
        return true;
    }

    // Convert glob pattern to regex
    let regex_pattern = pattern
        .replace('.', r"\.")
        .replace("**", "§DOUBLESTAR§") // Temporary placeholder
        .replace('*', r"[^.]*")
        .replace("§DOUBLESTAR§", ".*");

    Regex::new(&format!("^{}$", regex_pattern))
        .map(|re| re.is_match(rule_id))
        .unwrap_or(false)
}

// =============================================================================
// Configuration Parsers
// =============================================================================

/// Source of workspace settings.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingsSource {
    /// From pyproject.toml [tool.unfault]
    PyprojectToml,
    /// From Cargo.toml [package.metadata.unfault]
    CargoToml,
    /// From package.json "unfault" field
    PackageJson,
    /// From standalone unfault.toml
    UnfaultToml,
}

/// Result of loading workspace settings.
#[derive(Debug, Clone)]
pub struct LoadedSettings {
    /// The settings that were loaded.
    pub settings: WorkspaceSettings,
    /// Where the settings came from.
    pub source: SettingsSource,
    /// Path to the configuration file.
    pub path: String,
}

/// Load workspace settings from a project directory.
///
/// Tries sources in order of priority:
/// 1. `pyproject.toml` [tool.unfault]
/// 2. `Cargo.toml` [package.metadata.unfault]
/// 3. `package.json` "unfault" field
/// 4. `unfault.toml` (standalone fallback)
///
/// Returns `None` if no configuration is found.
pub fn load_settings(project_dir: &Path) -> Option<LoadedSettings> {
    // Try manifest files first (they take precedence)

    // 1. pyproject.toml
    let pyproject_path = project_dir.join("pyproject.toml");
    if pyproject_path.exists() {
        if let Some(settings) = parse_pyproject_toml(&pyproject_path) {
            return Some(LoadedSettings {
                settings,
                source: SettingsSource::PyprojectToml,
                path: pyproject_path.to_string_lossy().to_string(),
            });
        }
    }

    // 2. Cargo.toml
    let cargo_path = project_dir.join("Cargo.toml");
    if cargo_path.exists() {
        if let Some(settings) = parse_cargo_toml(&cargo_path) {
            return Some(LoadedSettings {
                settings,
                source: SettingsSource::CargoToml,
                path: cargo_path.to_string_lossy().to_string(),
            });
        }
    }

    // 3. package.json
    let package_json_path = project_dir.join("package.json");
    if package_json_path.exists() {
        if let Some(settings) = parse_package_json(&package_json_path) {
            return Some(LoadedSettings {
                settings,
                source: SettingsSource::PackageJson,
                path: package_json_path.to_string_lossy().to_string(),
            });
        }
    }

    // 4. unfault.toml (standalone fallback)
    let unfault_toml_path = project_dir.join("unfault.toml");
    if unfault_toml_path.exists() {
        if let Some(settings) = parse_unfault_toml(&unfault_toml_path) {
            return Some(LoadedSettings {
                settings,
                source: SettingsSource::UnfaultToml,
                path: unfault_toml_path.to_string_lossy().to_string(),
            });
        }
    }

    None
}

/// Parse [tool.unfault] from pyproject.toml.
fn parse_pyproject_toml(path: &Path) -> Option<WorkspaceSettings> {
    let contents = fs::read_to_string(path).ok()?;
    let doc: toml::Value = toml::from_str(&contents).ok()?;

    let tool_unfault = doc.get("tool")?.get("unfault")?;
    parse_toml_settings(tool_unfault)
}

/// Parse [package.metadata.unfault] from Cargo.toml.
fn parse_cargo_toml(path: &Path) -> Option<WorkspaceSettings> {
    let contents = fs::read_to_string(path).ok()?;
    let doc: toml::Value = toml::from_str(&contents).ok()?;

    let metadata_unfault = doc.get("package")?.get("metadata")?.get("unfault")?;
    parse_toml_settings(metadata_unfault)
}

/// Parse standalone unfault.toml.
fn parse_unfault_toml(path: &Path) -> Option<WorkspaceSettings> {
    let contents = fs::read_to_string(path).ok()?;
    let settings: WorkspaceSettings = toml::from_str(&contents).ok()?;
    Some(settings)
}

/// Parse unfault field from package.json.
fn parse_package_json(path: &Path) -> Option<WorkspaceSettings> {
    let contents = fs::read_to_string(path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&contents).ok()?;

    let unfault = doc.get("unfault")?;
    let settings: WorkspaceSettings = serde_json::from_value(unfault.clone()).ok()?;
    Some(settings)
}

/// Parse TOML value into WorkspaceSettings.
fn parse_toml_settings(value: &toml::Value) -> Option<WorkspaceSettings> {
    // Convert toml::Value to JSON for uniform parsing
    let json_str = serde_json::to_string(value).ok()?;
    serde_json::from_str(&json_str).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // =============================================================================
    // Glob Matching Tests
    // =============================================================================

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match(
            "python.http.missing_timeout",
            "python.http.missing_timeout"
        ));
        assert!(!glob_match(
            "python.http.missing_timeout",
            "python.http.missing_retry"
        ));
    }

    #[test]
    fn test_glob_match_single_star() {
        // Single star matches within a segment (not across dots)
        assert!(glob_match("python.http.*", "python.http.missing_timeout"));
        assert!(glob_match("python.http.*", "python.http.missing_retry"));
        assert!(!glob_match("python.http.*", "python.http.client.timeout"));
        assert!(!glob_match("python.http.*", "go.http.missing_timeout"));
    }

    #[test]
    fn test_glob_match_star_prefix() {
        assert!(glob_match("*.missing_timeout", "python.missing_timeout"));
        assert!(glob_match("*.missing_timeout", "go.missing_timeout"));
        assert!(!glob_match(
            "*.missing_timeout",
            "python.http.missing_timeout"
        ));
    }

    #[test]
    fn test_glob_match_double_star() {
        // Double star matches across dots
        assert!(glob_match("python.**", "python.http.missing_timeout"));
        assert!(glob_match("python.**", "python.bare_except"));
        assert!(glob_match("python.**", "python.http.client.timeout"));
        assert!(!glob_match("python.**", "go.http.missing_timeout"));
    }

    #[test]
    fn test_glob_match_invalid_regex() {
        // Invalid patterns should return false, not panic
        assert!(!glob_match("[invalid", "python.http"));
    }

    // =============================================================================
    // WorkspaceSettings Tests
    // =============================================================================

    #[test]
    fn test_workspace_settings_default() {
        let settings = WorkspaceSettings::default();
        assert!(settings.is_empty());
        assert!(settings.profile.is_none());
        assert!(settings.dimensions.is_none());
        assert!(settings.rules.exclude.is_empty());
    }

    #[test]
    fn test_workspace_settings_is_rule_excluded() {
        let settings = WorkspaceSettings {
            rules: RuleSettings {
                exclude: vec!["python.http.*".to_string(), "go.bare_recover".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(settings.is_rule_excluded("python.http.missing_timeout"));
        assert!(settings.is_rule_excluded("python.http.missing_retry"));
        assert!(settings.is_rule_excluded("go.bare_recover"));
        assert!(!settings.is_rule_excluded("python.bare_except"));
    }

    #[test]
    fn test_workspace_settings_is_rule_included() {
        let settings = WorkspaceSettings {
            rules: RuleSettings {
                include: vec!["python.security.*".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(settings.is_rule_included("python.security.sql_injection"));
        assert!(!settings.is_rule_included("python.http.missing_timeout"));
    }

    #[test]
    fn test_workspace_settings_get_severity_override() {
        let mut severity = HashMap::new();
        severity.insert("python.bare_except".to_string(), "low".to_string());

        let settings = WorkspaceSettings {
            rules: RuleSettings {
                severity,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(
            settings.get_severity_override("python.bare_except"),
            Some("low")
        );
        assert_eq!(
            settings.get_severity_override("python.http.missing_timeout"),
            None
        );
    }

    #[test]
    fn test_workspace_settings_filter_rules() {
        let settings = WorkspaceSettings {
            rules: RuleSettings {
                exclude: vec!["python.http.*".to_string()],
                include: vec!["python.security.sql_injection".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let profile_rules = vec![
            "python.http.missing_timeout".to_string(),
            "python.http.missing_retry".to_string(),
            "python.bare_except".to_string(),
        ];
        let all_rules = vec![
            "python.http.missing_timeout".to_string(),
            "python.http.missing_retry".to_string(),
            "python.bare_except".to_string(),
            "python.security.sql_injection".to_string(),
            "python.security.hardcoded_secrets".to_string(),
        ];

        let filtered = settings.filter_rules(&profile_rules, &all_rules);

        // HTTP rules should be excluded
        assert!(!filtered.contains(&"python.http.missing_timeout".to_string()));
        assert!(!filtered.contains(&"python.http.missing_retry".to_string()));
        // bare_except should remain
        assert!(filtered.contains(&"python.bare_except".to_string()));
        // sql_injection should be added
        assert!(filtered.contains(&"python.security.sql_injection".to_string()));
    }

    // =============================================================================
    // Serialization Tests
    // =============================================================================

    #[test]
    fn test_workspace_settings_serialize_json() {
        let settings = WorkspaceSettings {
            profile: Some("python_fastapi_backend".to_string()),
            dimensions: Some(vec!["stability".to_string()]),
            rules: RuleSettings {
                exclude: vec!["python.http.*".to_string()],
                include: vec![],
                severity: HashMap::new(),
            },
        };

        let json = serde_json::to_string(&settings).unwrap();
        assert!(json.contains("python_fastapi_backend"));
        assert!(json.contains("stability"));
        assert!(json.contains("python.http.*"));
    }

    #[test]
    fn test_workspace_settings_deserialize_json() {
        let json = r#"{
            "profile": "python_fastapi_backend",
            "dimensions": ["stability", "correctness"],
            "rules": {
                "exclude": ["python.http.*"],
                "include": ["python.security.*"],
                "severity": {
                    "python.bare_except": "low"
                }
            }
        }"#;

        let settings: WorkspaceSettings = serde_json::from_str(json).unwrap();

        assert_eq!(settings.profile, Some("python_fastapi_backend".to_string()));
        assert_eq!(
            settings.dimensions,
            Some(vec!["stability".to_string(), "correctness".to_string()])
        );
        assert_eq!(settings.rules.exclude, vec!["python.http.*"]);
        assert_eq!(settings.rules.include, vec!["python.security.*"]);
        assert_eq!(
            settings.rules.severity.get("python.bare_except"),
            Some(&"low".to_string())
        );
    }

    #[test]
    fn test_workspace_settings_deserialize_minimal_json() {
        let json = r#"{
            "rules": {
                "exclude": ["python.missing_structured_logging"]
            }
        }"#;

        let settings: WorkspaceSettings = serde_json::from_str(json).unwrap();

        assert!(settings.profile.is_none());
        assert!(settings.dimensions.is_none());
        assert_eq!(
            settings.rules.exclude,
            vec!["python.missing_structured_logging"]
        );
        assert!(settings.rules.include.is_empty());
    }

    // =============================================================================
    // Parser Tests
    // =============================================================================

    #[test]
    fn test_parse_pyproject_toml() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");

        fs::write(
            &pyproject_path,
            r#"
[project]
name = "my-project"

[tool.unfault]
profile = "python_fastapi_backend"
dimensions = ["stability"]

[tool.unfault.rules]
exclude = ["python.http.*"]
include = ["python.security.*"]

[tool.unfault.rules.severity]
"python.bare_except" = "low"
"#,
        )
        .unwrap();

        let settings = parse_pyproject_toml(&pyproject_path).unwrap();

        assert_eq!(settings.profile, Some("python_fastapi_backend".to_string()));
        assert_eq!(settings.dimensions, Some(vec!["stability".to_string()]));
        assert_eq!(settings.rules.exclude, vec!["python.http.*"]);
        assert_eq!(settings.rules.include, vec!["python.security.*"]);
        assert_eq!(
            settings.rules.severity.get("python.bare_except"),
            Some(&"low".to_string())
        );
    }

    #[test]
    fn test_parse_pyproject_toml_no_unfault_section() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");

        fs::write(
            &pyproject_path,
            r#"
[project]
name = "my-project"

[tool.black]
line-length = 100
"#,
        )
        .unwrap();

        let settings = parse_pyproject_toml(&pyproject_path);
        assert!(settings.is_none());
    }

    #[test]
    fn test_parse_cargo_toml() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_path = temp_dir.path().join("Cargo.toml");

        fs::write(
            &cargo_path,
            r#"
[package]
name = "my-crate"
version = "0.1.0"

[package.metadata.unfault]
profile = "rust_axum_service"
dimensions = ["stability", "correctness"]

[package.metadata.unfault.rules]
exclude = ["rust.println_in_lib"]

[package.metadata.unfault.rules.severity]
"rust.unsafe_unwrap" = "critical"
"#,
        )
        .unwrap();

        let settings = parse_cargo_toml(&cargo_path).unwrap();

        assert_eq!(settings.profile, Some("rust_axum_service".to_string()));
        assert_eq!(
            settings.dimensions,
            Some(vec!["stability".to_string(), "correctness".to_string()])
        );
        assert_eq!(settings.rules.exclude, vec!["rust.println_in_lib"]);
        assert_eq!(
            settings.rules.severity.get("rust.unsafe_unwrap"),
            Some(&"critical".to_string())
        );
    }

    #[test]
    fn test_parse_cargo_toml_no_unfault_section() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_path = temp_dir.path().join("Cargo.toml");

        fs::write(
            &cargo_path,
            r#"
[package]
name = "my-crate"
version = "0.1.0"
"#,
        )
        .unwrap();

        let settings = parse_cargo_toml(&cargo_path);
        assert!(settings.is_none());
    }

    #[test]
    fn test_parse_package_json() {
        let temp_dir = TempDir::new().unwrap();
        let package_path = temp_dir.path().join("package.json");

        fs::write(
            &package_path,
            r#"{
    "name": "my-app",
    "version": "1.0.0",
    "unfault": {
        "profile": "typescript_express_backend",
        "dimensions": ["stability", "security"],
        "rules": {
            "exclude": ["typescript.console_in_production"],
            "severity": {
                "typescript.empty_catch": "critical"
            }
        }
    }
}"#,
        )
        .unwrap();

        let settings = parse_package_json(&package_path).unwrap();

        assert_eq!(
            settings.profile,
            Some("typescript_express_backend".to_string())
        );
        assert_eq!(
            settings.dimensions,
            Some(vec!["stability".to_string(), "security".to_string()])
        );
        assert_eq!(
            settings.rules.exclude,
            vec!["typescript.console_in_production"]
        );
        assert_eq!(
            settings.rules.severity.get("typescript.empty_catch"),
            Some(&"critical".to_string())
        );
    }

    #[test]
    fn test_parse_package_json_no_unfault_field() {
        let temp_dir = TempDir::new().unwrap();
        let package_path = temp_dir.path().join("package.json");

        fs::write(
            &package_path,
            r#"{
    "name": "my-app",
    "version": "1.0.0"
}"#,
        )
        .unwrap();

        let settings = parse_package_json(&package_path);
        assert!(settings.is_none());
    }

    #[test]
    fn test_parse_unfault_toml() {
        let temp_dir = TempDir::new().unwrap();
        let unfault_path = temp_dir.path().join("unfault.toml");

        fs::write(
            &unfault_path,
            r#"
profile = "go_gin_service"
dimensions = ["stability", "performance"]

[rules]
exclude = ["go.missing_structured_logging"]
include = ["go.security.*"]

[rules.severity]
"go.unchecked_error" = "critical"
"#,
        )
        .unwrap();

        let settings = parse_unfault_toml(&unfault_path).unwrap();

        assert_eq!(settings.profile, Some("go_gin_service".to_string()));
        assert_eq!(
            settings.dimensions,
            Some(vec!["stability".to_string(), "performance".to_string()])
        );
        assert_eq!(
            settings.rules.exclude,
            vec!["go.missing_structured_logging"]
        );
        assert_eq!(settings.rules.include, vec!["go.security.*"]);
        assert_eq!(
            settings.rules.severity.get("go.unchecked_error"),
            Some(&"critical".to_string())
        );
    }

    // =============================================================================
    // Load Settings Tests (Priority)
    // =============================================================================

    #[test]
    fn test_load_settings_priority_pyproject_wins() {
        let temp_dir = TempDir::new().unwrap();

        // Create both pyproject.toml and unfault.toml
        fs::write(
            temp_dir.path().join("pyproject.toml"),
            r#"
[tool.unfault]
profile = "python_from_pyproject"
"#,
        )
        .unwrap();

        fs::write(
            temp_dir.path().join("unfault.toml"),
            r#"
profile = "from_unfault_toml"
"#,
        )
        .unwrap();

        let loaded = load_settings(temp_dir.path()).unwrap();

        assert_eq!(loaded.source, SettingsSource::PyprojectToml);
        assert_eq!(
            loaded.settings.profile,
            Some("python_from_pyproject".to_string())
        );
    }

    #[test]
    fn test_load_settings_fallback_to_unfault_toml() {
        let temp_dir = TempDir::new().unwrap();

        // Create only unfault.toml
        fs::write(
            temp_dir.path().join("unfault.toml"),
            r#"
profile = "go_gin_service"
"#,
        )
        .unwrap();

        let loaded = load_settings(temp_dir.path()).unwrap();

        assert_eq!(loaded.source, SettingsSource::UnfaultToml);
        assert_eq!(loaded.settings.profile, Some("go_gin_service".to_string()));
    }

    #[test]
    fn test_load_settings_none_when_no_config() {
        let temp_dir = TempDir::new().unwrap();

        let loaded = load_settings(temp_dir.path());
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_settings_skip_invalid_pyproject() {
        let temp_dir = TempDir::new().unwrap();

        // Create pyproject.toml without [tool.unfault]
        fs::write(
            temp_dir.path().join("pyproject.toml"),
            r#"
[project]
name = "test"
"#,
        )
        .unwrap();

        // Create valid unfault.toml as fallback
        fs::write(
            temp_dir.path().join("unfault.toml"),
            r#"
profile = "fallback"
"#,
        )
        .unwrap();

        let loaded = load_settings(temp_dir.path()).unwrap();

        // Should fall through to unfault.toml since pyproject.toml has no [tool.unfault]
        assert_eq!(loaded.source, SettingsSource::UnfaultToml);
        assert_eq!(loaded.settings.profile, Some("fallback".to_string()));
    }
}

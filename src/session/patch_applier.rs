//! Patch Applier Module
//!
//! This module provides functionality to apply patches from analysis findings
//! to local source files. It supports two patching strategies:
//!
//! 1. **Byte-offset patching**: Uses precise byte offsets from the finding
//!    (most accurate, used when byte_start/byte_end are provided)
//!
//! 2. **Line-based patching**: Falls back to line/column information
//!    (used when byte offsets are not available)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use unfault::session::patch_applier::PatchApplier;
//!
//! let applier = PatchApplier::new(&workspace_path);
//! let stats = applier.apply_findings(&findings, dry_run)?;
//! println!("Applied {} patches", stats.applied);
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::api::graph::IrFinding;

/// Statistics from a patch application session
#[derive(Debug, Default, Clone)]
pub struct PatchStats {
    /// Number of patches successfully applied
    pub applied: usize,
    /// Number of patches skipped (no patch data)
    pub skipped: usize,
    /// Number of patches that failed to apply
    pub failed: usize,
    /// Files that were modified
    pub modified_files: Vec<String>,
    /// Error messages for failed patches
    pub errors: Vec<String>,
}

impl PatchStats {
    /// Returns true if all patches were applied successfully
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
}

/// A single patch to apply to a file
#[derive(Debug)]
struct Patch {
    /// Start byte offset (0-indexed)
    byte_start: usize,
    /// End byte offset (0-indexed, exclusive)
    byte_end: usize,
    /// Replacement text
    replacement: String,
    /// Rule ID for logging (kept for future use in diagnostics)
    #[allow(dead_code)]
    rule_id: String,
}

impl Patch {
    /// Create a patch from an IrFinding if it has the necessary information
    fn from_finding(finding: &IrFinding, file_content: &str) -> Option<Self> {
        // Need patch content
        let patch_diff = finding.patch.as_ref()?;

        // Extract replacement from unified diff
        let replacement = extract_replacement_from_diff(patch_diff)?;

        // Prefer byte offsets if available
        if let (Some(start), Some(end)) = (finding.byte_start, finding.byte_end) {
            return Some(Patch {
                byte_start: start,
                byte_end: end,
                replacement,
                rule_id: finding.rule_id.clone(),
            });
        }

        // Fall back to line/column calculation
        // Use end_line/end_column if available, otherwise default to same line as start
        let end_line = finding.end_line.unwrap_or(finding.line);
        let end_column = finding.end_column.unwrap_or(finding.column + 1);
        let (byte_start, byte_end) = line_col_to_bytes(
            file_content,
            finding.line,
            finding.column,
            end_line,
            end_column,
        )?;

        Some(Patch {
            byte_start,
            byte_end,
            replacement,
            rule_id: finding.rule_id.clone(),
        })
    }
}

/// Extract the replacement text from a unified diff.
///
/// For a unified diff, returns the lines starting with `+` (excluding
/// the `+++` header). For deletion-only diffs, returns an empty string.
/// Returns `None` if there are no additions or deletions.
fn extract_replacement_from_diff(diff: &str) -> Option<String> {
    let mut additions = Vec::new();

    for line in diff.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            // Remove the leading '+' and keep the content
            additions.push(&line[1..]);
        }
    }

    if additions.is_empty() {
        // Check if this is a deletion-only diff
        let has_deletions = diff
            .lines()
            .any(|l| l.starts_with('-') && !l.starts_with("---"));
        if has_deletions {
            // Pure deletion - replace with empty string
            return Some(String::new());
        }
        return None;
    }

    Some(additions.join("\n"))
}

/// Convert line/column positions to byte offsets.
///
/// Line and column are 1-indexed.
fn line_col_to_bytes(
    content: &str,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
) -> Option<(usize, usize)> {
    let lines: Vec<&str> = content.lines().collect();

    // Convert to 0-indexed
    let start_line_idx = (start_line as usize).saturating_sub(1);
    let end_line_idx = (end_line as usize).saturating_sub(1);

    if start_line_idx >= lines.len() || end_line_idx >= lines.len() {
        return None;
    }

    // Calculate byte offset for start position
    let mut byte_start = 0;
    for (i, line) in lines.iter().enumerate() {
        if i == start_line_idx {
            // Add column offset (convert to 0-indexed)
            let col_offset = (start_col as usize).saturating_sub(1);
            byte_start += col_offset.min(line.len());
            break;
        }
        // Add line length plus newline
        byte_start += line.len() + 1;
    }

    // Calculate byte offset for end position
    let mut byte_end = 0;
    for (i, line) in lines.iter().enumerate() {
        if i == end_line_idx {
            let col_offset = (end_col as usize).saturating_sub(1);
            byte_end += col_offset.min(line.len());
            break;
        }
        byte_end += line.len() + 1;
    }

    Some((byte_start, byte_end))
}

/// Applies patches from analysis findings to source files.
pub struct PatchApplier {
    /// Workspace root directory
    workspace_path: PathBuf,
}

impl PatchApplier {
    /// Create a new PatchApplier for a workspace.
    pub fn new(workspace_path: &Path) -> Self {
        Self {
            workspace_path: workspace_path.to_path_buf(),
        }
    }

    /// Apply patches from findings to source files.
    ///
    /// # Arguments
    ///
    /// * `findings` - List of findings with patches to apply
    /// * `dry_run` - If true, don't actually modify files, just report what would change
    ///
    /// # Returns
    ///
    /// Statistics about the patch application.
    pub fn apply_findings(&self, findings: &[IrFinding], dry_run: bool) -> Result<PatchStats> {
        let mut stats = PatchStats::default();

        // Group findings by file
        let mut findings_by_file: HashMap<String, Vec<&IrFinding>> = HashMap::new();
        for finding in findings {
            if finding.patch.is_some() {
                findings_by_file
                    .entry(finding.file_path.clone())
                    .or_default()
                    .push(finding);
            } else {
                stats.skipped += 1;
            }
        }

        // Process each file
        for (file_path, file_findings) in findings_by_file {
            match self.apply_file_patches(&file_path, &file_findings, dry_run) {
                Ok(applied_count) => {
                    stats.applied += applied_count;
                    if applied_count > 0 && !dry_run {
                        stats.modified_files.push(file_path);
                    }
                }
                Err(e) => {
                    stats.failed += file_findings.len();
                    stats.errors.push(format!("{}: {}", file_path, e));
                }
            }
        }

        Ok(stats)
    }

    /// Apply patches to a single file.
    fn apply_file_patches(
        &self,
        file_path: &str,
        findings: &[&IrFinding],
        dry_run: bool,
    ) -> Result<usize> {
        let full_path = self.workspace_path.join(file_path);
        let content = fs::read_to_string(&full_path)
            .with_context(|| format!("Failed to read {}", file_path))?;

        // Convert findings to patches
        let mut patches: Vec<Patch> = findings
            .iter()
            .filter_map(|f| Patch::from_finding(f, &content))
            .collect();

        if patches.is_empty() {
            return Ok(0);
        }

        // Sort patches by byte_start in descending order
        // This allows us to apply patches from end to start, preserving offsets
        patches.sort_by(|a, b| b.byte_start.cmp(&a.byte_start));

        // Apply patches
        let mut modified_content = content.clone();
        let mut applied_count = 0;

        for patch in &patches {
            if patch.byte_end > modified_content.len() {
                // Patch extends beyond file bounds, skip
                continue;
            }

            // Apply the patch
            modified_content = format!(
                "{}{}{}",
                &modified_content[..patch.byte_start],
                &patch.replacement,
                &modified_content[patch.byte_end..]
            );
            applied_count += 1;
        }

        // Write the modified content
        if !dry_run && applied_count > 0 {
            fs::write(&full_path, &modified_content)
                .with_context(|| format!("Failed to write {}", file_path))?;
        }

        Ok(applied_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_extract_replacement_from_diff_simple() {
        let diff = r#"--- a/test.py
+++ b/test.py
@@ -10,1 +10,1 @@
-old_line()
+new_line(timeout=30)"#;

        let replacement = extract_replacement_from_diff(diff);
        assert_eq!(replacement, Some("new_line(timeout=30)".to_string()));
    }

    #[test]
    fn test_extract_replacement_from_diff_multiline() {
        let diff = r#"--- a/test.py
+++ b/test.py
@@ -1,2 +1,3 @@
-old1
-old2
+new1
+new2
+new3"#;

        let replacement = extract_replacement_from_diff(diff);
        assert_eq!(replacement, Some("new1\nnew2\nnew3".to_string()));
    }

    #[test]
    fn test_extract_replacement_from_diff_deletion() {
        let diff = r#"--- a/test.py
+++ b/test.py
@@ -1,1 +0,0 @@
-to_delete()"#;

        let replacement = extract_replacement_from_diff(diff);
        assert_eq!(replacement, Some(String::new()));
    }

    #[test]
    fn test_line_col_to_bytes() {
        let content = "line1\nline2\nline3";
        // line1 is at bytes 0-5 (including newline at pos 5)
        // line2 is at bytes 6-11 (including newline at pos 11)
        // line3 is at bytes 12-17

        // Start of line 1
        let result = line_col_to_bytes(content, 1, 1, 1, 5);
        assert_eq!(result, Some((0, 4)));

        // Start of line 2
        let result = line_col_to_bytes(content, 2, 1, 2, 5);
        assert_eq!(result, Some((6, 10)));
    }

    #[test]
    fn test_patch_applier_dry_run() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        fs::write(&file_path, "requests.get(url)\n").unwrap();

        let applier = PatchApplier::new(temp_dir.path());

        let findings = vec![IrFinding {
            rule_id: "test.rule".to_string(),
            title: String::new(),
            description: String::new(),
            severity: "high".to_string(),
            dimension: String::new(),
            file_path: "test.py".to_string(),
            line: 1,
            column: 1,
            end_line: Some(1),
            end_column: Some(18),
            message: "Add timeout".to_string(),
            patch_json: None,
            fix_preview: None,
            applicability_json: None,
            patch: Some(
                r#"--- a/test.py
+++ b/test.py
@@ -1,1 +1,1 @@
-requests.get(url)
+requests.get(url, timeout=30)"#
                    .to_string(),
            ),
            byte_start: Some(0),
            byte_end: Some(17),
        }];

        let stats = applier.apply_findings(&findings, true).unwrap();
        assert_eq!(stats.applied, 1);
        assert_eq!(stats.modified_files.len(), 0); // Dry run, no files modified

        // Verify file wasn't changed
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "requests.get(url)\n");
    }

    #[test]
    fn test_patch_applier_apply() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        fs::write(&file_path, "requests.get(url)\n").unwrap();

        let applier = PatchApplier::new(temp_dir.path());

        let findings = vec![IrFinding {
            rule_id: "test.rule".to_string(),
            title: String::new(),
            description: String::new(),
            severity: "high".to_string(),
            dimension: String::new(),
            file_path: "test.py".to_string(),
            line: 1,
            column: 1,
            end_line: Some(1),
            end_column: Some(18),
            message: "Add timeout".to_string(),
            patch_json: None,
            fix_preview: None,
            applicability_json: None,
            patch: Some(
                r#"--- a/test.py
+++ b/test.py
@@ -1,1 +1,1 @@
-requests.get(url)
+requests.get(url, timeout=30)"#
                    .to_string(),
            ),
            byte_start: Some(0),
            byte_end: Some(17),
        }];

        let stats = applier.apply_findings(&findings, false).unwrap();
        assert_eq!(stats.applied, 1);
        assert_eq!(stats.modified_files.len(), 1);

        // Verify file was changed
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "requests.get(url, timeout=30)\n");
    }

    #[test]
    fn test_patch_applier_multiple_patches_same_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        fs::write(&file_path, "requests.get(url1)\nrequests.get(url2)\n").unwrap();

        let applier = PatchApplier::new(temp_dir.path());

        let findings = vec![
            IrFinding {
                rule_id: "test.rule".to_string(),
                title: String::new(),
                description: String::new(),
                severity: "high".to_string(),
                dimension: String::new(),
                file_path: "test.py".to_string(),
                line: 1,
                column: 1,
                end_line: Some(1),
                end_column: Some(18),
                message: "Add timeout".to_string(),
                patch_json: None,
                fix_preview: None,
                applicability_json: None,
                patch: Some(
                    r#"--- a/test.py
+++ b/test.py
@@ -1,1 +1,1 @@
-requests.get(url1)
+requests.get(url1, timeout=30)"#
                        .to_string(),
                ),
                byte_start: Some(0),
                byte_end: Some(18),
            },
            IrFinding {
                rule_id: "test.rule".to_string(),
                title: String::new(),
                description: String::new(),
                severity: "high".to_string(),
                dimension: String::new(),
                file_path: "test.py".to_string(),
                line: 2,
                column: 1,
                end_line: Some(2),
                end_column: Some(18),
                message: "Add timeout".to_string(),
                patch_json: None,
                fix_preview: None,
                applicability_json: None,
                patch: Some(
                    r#"--- a/test.py
+++ b/test.py
@@ -2,1 +2,1 @@
-requests.get(url2)
+requests.get(url2, timeout=30)"#
                        .to_string(),
                ),
                byte_start: Some(19),
                byte_end: Some(37),
            },
        ];

        let stats = applier.apply_findings(&findings, false).unwrap();
        assert_eq!(stats.applied, 2);

        // Verify file was changed correctly
        let content = fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("timeout=30"));
        // Both lines should have timeouts
        assert_eq!(content.matches("timeout=30").count(), 2);
    }

    #[test]
    fn test_patch_applier_skip_no_patch() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        fs::write(&file_path, "requests.get(url)\n").unwrap();

        let applier = PatchApplier::new(temp_dir.path());

        let findings = vec![IrFinding {
            rule_id: "test.rule".to_string(),
            title: String::new(),
            description: String::new(),
            severity: "high".to_string(),
            dimension: String::new(),
            file_path: "test.py".to_string(),
            line: 1,
            column: 1,
            end_line: Some(1),
            end_column: Some(18),
            message: "Add timeout".to_string(),
            patch_json: None,
            fix_preview: None,
            applicability_json: None,
            patch: None, // No patch
            byte_start: None,
            byte_end: None,
        }];

        let stats = applier.apply_findings(&findings, false).unwrap();
        assert_eq!(stats.applied, 0);
        assert_eq!(stats.skipped, 1);
    }

    #[test]
    fn test_patch_stats_is_success() {
        let mut stats = PatchStats::default();
        assert!(stats.is_success());

        stats.applied = 5;
        assert!(stats.is_success());

        stats.failed = 1;
        assert!(!stats.is_success());
    }
}

// unfault-ignore: rust.println_in_lib
//! # Review Command
//!
//! Implements the code review/analysis command for the Unfault CLI.
//!
//! ## Workflow
//!
//! 1. Load configuration and verify authentication
//! 2. Scan the current directory for source files using [`WorkspaceScanner`]
//! 3. Detect project type and frameworks
//! 4. Create an analysis session with the API
//! 5. Collect files based on file hints using [`FileCollector`]
//! 6. Run analysis using [`SessionRunner`] and display results
//!
//! ## Usage
//!
//! ```bash
//! unfault review
//! unfault review --output full
//! unfault review --output json
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::api::{ApiClient, ApiError, SubscriptionWarning};
use crate::config::Config;
use crate::errors::{
    display_auth_error, display_config_error, display_network_error, display_service_error,
};
use crate::exit_codes::*;
use crate::session::{FileCollector, ScanProgress, SessionRunner, WorkspaceScanner};

/// Display a subscription warning banner (non-blocking nudge).
///
/// This is used to inform users about trial expiration without blocking their workflow.
fn display_subscription_warning(warning: &SubscriptionWarning) {
    let icon = match warning.warning_type.as_str() {
        "trial_ending" => "ℹ",
        "trial_expired" => "⚠",
        _ => "ℹ",
    };

    let color = match warning.warning_type.as_str() {
        "trial_ending" => "cyan",
        "trial_expired" => "yellow",
        _ => "white",
    };

    eprintln!();
    eprintln!(
        "{} {}",
        icon.color(color).bold(),
        warning.message.color(color)
    );
    eprintln!(
        "  Subscribe at: {}",
        warning.upgrade_url.underline().bright_blue()
    );
    eprintln!();
}

/// Display a message about limited results due to expired trial.
fn display_limited_results_notice(shown_count: usize, total_count: i32) {
    let hidden_count = total_count as usize - shown_count;
    if hidden_count > 0 {
        eprintln!();
        eprintln!(
            "  {} {} more issue{} available with subscription",
            "→".bright_blue(),
            hidden_count.to_string().bright_yellow(),
            if hidden_count == 1 { "" } else { "s" }
        );
    }
}

/// Handle an API error and return the appropriate exit code.
fn handle_api_error(error: ApiError) -> i32 {
    match error {
        ApiError::Unauthorized { message } => {
            display_auth_error(&message);
            EXIT_AUTH_ERROR
        }
        ApiError::Forbidden { message } => {
            display_auth_error(&message);
            EXIT_AUTH_ERROR
        }
        ApiError::Network { message } => {
            display_network_error(&message);
            EXIT_NETWORK_ERROR
        }
        ApiError::Server { status, message } => {
            display_service_error(&format!("HTTP {} - {}", status, message));
            EXIT_NETWORK_ERROR
        }
        ApiError::ClientError { status, message } => {
            display_network_error(&format!("HTTP {} - {}", status, message));
            EXIT_NETWORK_ERROR
        }
        ApiError::ParseError { message } => {
            display_network_error(&message);
            EXIT_NETWORK_ERROR
        }
    }
}

/// Arguments for the review command
pub struct ReviewArgs {
    /// Output format (text or json)
    pub output_format: String,
    /// Output mode (concise or full)
    pub output_mode: String,
    /// Verbose mode (dump raw responses)
    pub verbose: bool,
    /// Override the detected profile
    pub profile: Option<String>,
    /// Dimensions to analyze (None = all from profile)
    pub dimensions: Option<Vec<String>>,
}

/// Execute the review command
///
/// Analyzes the current directory and displays findings.
///
/// # Arguments
///
/// * `args` - Review command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Analysis completed with no findings
/// * `Ok(EXIT_FINDINGS_FOUND)` - Analysis completed with findings
/// * `Ok(EXIT_CONFIG_ERROR)` - Configuration error
/// * `Ok(EXIT_AUTH_ERROR)` - Authentication error
/// * `Ok(EXIT_NETWORK_ERROR)` - Network error
/// State for progressive display during scanning.
#[derive(Default)]
struct ScanDisplayState {
    languages: Vec<String>,
    frameworks: Vec<String>,
    file_count: usize,
    lines_printed: usize,
}

impl ScanDisplayState {
    /// Update the display with new progress.
    fn update(&mut self, progress: &ScanProgress) {
        self.file_count = progress.file_count;
        self.languages = progress.languages.clone();
        self.frameworks = progress.frameworks.clone();
    }

    /// Render the current state to the terminal, overwriting previous lines.
    fn render(&mut self, dimensions: &[String], profile_override: Option<&str>) {
        // Move cursor up to overwrite previous lines
        if self.lines_printed > 0 {
            // Move up and clear each line
            for _ in 0..self.lines_printed {
                eprint!("\x1b[1A\x1b[2K");
            }
        }

        let mut lines = 0;

        // Languages line
        if !self.languages.is_empty() {
            eprintln!("  Languages: {}", self.languages.join(", ").cyan());
            lines += 1;
        }

        // Frameworks line
        if !self.frameworks.is_empty() {
            eprintln!("  Frameworks: {}", self.frameworks.join(", ").cyan());
            lines += 1;
        }

        // Profile override line
        if let Some(profile) = profile_override {
            eprintln!("  Profile: {} (override)", profile.cyan());
            lines += 1;
        }

        // Dimensions line
        eprintln!("  Dimensions: {}", dimensions.join(", ").cyan());
        lines += 1;

        // File count line (always show, even if 0)
        eprintln!(
            "  Found {} matching source files",
            self.file_count.to_string().bright_green()
        );
        lines += 1;

        self.lines_printed = lines;
        let _ = io::stderr().flush();
    }
}

pub async fn execute(args: ReviewArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            display_config_error(&format!("{}", e));
            eprintln!(
                "\n{} Run `unfault login` to authenticate first.",
                "Tip:".cyan().bold()
            );
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Create API client (env var takes precedence over config file)
    let api_client = ApiClient::new(config.base_url());
    let trace_id = api_client.trace_id.clone();

    // Get current directory
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;

    // Start timing the session
    let session_start = Instant::now();

    // Get workspace label first (just the directory name)
    let workspace_label = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace")
        .to_string();

    // Print header immediately
    eprintln!(
        "{} Analyzing {}...",
        "→".cyan().bold(),
        workspace_label.bright_blue()
    );

    // Determine dimensions to analyze (needed for display)
    let dimensions: Vec<String> = args.dimensions.clone().unwrap_or_else(|| {
        vec![
            "stability".to_string(),
            "correctness".to_string(),
            "performance".to_string(),
        ]
    });

    // Set up progressive display state
    let display_state = Arc::new(Mutex::new(ScanDisplayState::default()));
    let display_state_clone = Arc::clone(&display_state);
    let dimensions_clone = dimensions.clone();
    let profile_clone = args.profile.clone();

    // Initial render with 0 files
    {
        let mut state = display_state.lock().unwrap();
        state.render(&dimensions, args.profile.as_deref());
    }

    // Step 1: Scan workspace with progress callback
    let mut scanner = WorkspaceScanner::new(&current_dir).with_progress(move |progress| {
        let mut state = display_state_clone.lock().unwrap();
        state.update(&progress);
        state.render(&dimensions_clone, profile_clone.as_deref());
    });

    let workspace_info = scanner.scan().context("Failed to scan workspace")?;

    // Final render with complete info
    {
        let mut state = display_state.lock().unwrap();
        state.file_count = workspace_info.source_files.len();
        state.languages = workspace_info.language_strings();
        state.frameworks = workspace_info.framework_strings();
        state.render(&dimensions, args.profile.as_deref());
    }

    if workspace_info.source_files.is_empty() {
        eprintln!(
            "{} No source files found in the current directory.",
            "⚠".yellow().bold()
        );
        return Ok(EXIT_SUCCESS);
    }

    // Create progress bar for API operations
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    // Step 2: Create session
    pb.set_message("Creating analysis session...");

    let runner = SessionRunner::new(&api_client, &config.api_key);
    let session_response = match runner.create_session(&workspace_info, None).await {
        Ok(response) => response,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };

    // Display subscription warning if present (non-blocking nudge)
    if let Some(warning) = &session_response.subscription_warning {
        display_subscription_warning(warning);
    }

    if args.verbose {
        eprintln!("\n{} Trace ID: {}", "DEBUG".yellow(), trace_id.cyan());
        eprintln!(
            "\n{} Session created: {}",
            "DEBUG".yellow(),
            serde_json::to_string_pretty(&session_response).unwrap_or_default()
        );
    }

    // Step 3: Collect files based on file hints
    pb.set_message("Collecting files for analysis...");

    let collector = FileCollector::new(&current_dir);
    let collected_files = collector
        .collect(&session_response.file_hints, &workspace_info.source_files)
        .context("Failed to collect files")?;

    if args.verbose {
        eprintln!(
            "\n{} Collected {} files ({} bytes)",
            "DEBUG".yellow(),
            collected_files.files.len(),
            collected_files.total_bytes
        );
    }

    // Step 4: Run analysis
    // Use a single context - the engine runs all rules from the profile
    // The dimension is metadata for findings, not a filter
    pb.set_message("Running analysis...");

    let run_response = match runner
        .run_analysis(
            &session_response.session_id,
            &workspace_info,
            &collected_files,
            "all", // Single context covering all dimensions
        )
        .await
    {
        Ok(response) => response,
        Err(e) => {
            pb.finish_and_clear();
            return Ok(handle_api_error(e));
        }
    };

    // Note: Embeddings are generated lazily when the user runs `unfault ask`
    // This saves ~100-500ms per review for users who don't use the ask feature

    pb.finish_and_clear();

    // Calculate elapsed time
    let elapsed = session_start.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;

    // Display review time (file count already shown during scanning)
    eprintln!(
        "  Reviewed in {}ms (trace: {})",
        elapsed_ms.to_string().bright_cyan(),
        &trace_id[..8].dimmed()
    );

    if args.verbose {
        eprintln!(
            "\n{} Analysis response: {}",
            "DEBUG".yellow(),
            serde_json::to_string_pretty(&run_response).unwrap_or_default()
        );
    }

    // Display results
    let total_findings: usize = run_response.contexts.iter().map(|c| c.findings.len()).sum();

    let _matched_files = workspace_info.source_files.len();

    if args.output_format == "json" {
        // JSON output - include subscription and limited info
        let output = serde_json::json!({
            "session_id": run_response.session_id,
            "status": run_response.status,
            "findings_count": total_findings,
            "elapsed_ms": elapsed_ms,
            "contexts": run_response.contexts,
            "subscription_warning": run_response.subscription_warning,
            "is_limited": run_response.is_limited,
            "total_findings_count": run_response.total_findings_count,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        // Text output (basic or full)
        println!();

        // Display appropriate message based on findings count
        if total_findings == 0 {
            if run_response.is_limited {
                // No findings shown, but there might be more with subscription
                if let Some(total) = run_response.total_findings_count {
                    if total > 0 {
                        println!(
                            "{} {} issue{} found (subscribe for full results)",
                            "⚠".yellow().bold(),
                            total.to_string().bright_yellow(),
                            if total == 1 { "" } else { "s" }
                        );
                    } else {
                        println!(
                            "{} No issues found! Your code looks good.",
                            "✓".bright_green().bold()
                        );
                    }
                } else {
                    println!(
                        "{} No issues found! Your code looks good.",
                        "✓".bright_green().bold()
                    );
                }
            } else {
                println!(
                    "{} No issues found! Your code looks good.",
                    "✓".bright_green().bold()
                );
            }
        } else {
            // Show findings count with limited mode indicator if applicable
            if run_response.is_limited {
                if let Some(total) = run_response.total_findings_count {
                    println!(
                        "{} Found {} issue{} (showing {} of {})",
                        "⚠".yellow().bold(),
                        total.to_string().bright_yellow(),
                        if total == 1 { "" } else { "s" },
                        total_findings,
                        total
                    );
                } else {
                    println!(
                        "{} Found {} issue{} (limited)",
                        "⚠".yellow().bold(),
                        total_findings.to_string().bright_yellow(),
                        if total_findings == 1 { "" } else { "s" }
                    );
                }
            } else {
                println!(
                    "{} Found {} issue{}",
                    "⚠".yellow().bold(),
                    total_findings.to_string().bright_yellow(),
                    if total_findings == 1 { "" } else { "s" }
                );
            }
            println!();

            // Collect all findings
            let all_findings: Vec<&crate::api::Finding> = run_response
                .contexts
                .iter()
                .flat_map(|c| c.findings.iter())
                .collect();

            if args.output_mode == "full" {
                for finding in &all_findings {
                    display_finding(finding);
                }
            } else {
                // Basic mode: grouped display
                display_findings_grouped(&all_findings);
            }

            // Show limited results notice if applicable
            if run_response.is_limited {
                if let Some(total) = run_response.total_findings_count {
                    display_limited_results_notice(total_findings, total);
                }
            }
        }

        // Display subscription warning from run response if present and not already shown
        // (session response warning takes precedence, but run response may have updated message)
        if let Some(warning) = &run_response.subscription_warning {
            if session_response.subscription_warning.is_none() || run_response.is_limited {
                display_subscription_warning(warning);
            }
        }
    }

    if total_findings > 0 {
        Ok(EXIT_FINDINGS_FOUND)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

/// Display findings grouped by severity and rule_id (for basic mode)
fn display_findings_grouped(findings: &[&crate::api::Finding]) {
    use std::collections::BTreeMap;

    // Define severity order (Critical first, then High, Medium, Low)
    let severity_order = |s: &str| -> u8 {
        match s {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            _ => 4,
        }
    };

    // Group findings by severity, then by rule_id
    // BTreeMap<severity_order, BTreeMap<rule_id, Vec<Finding>>>
    let mut grouped: BTreeMap<u8, BTreeMap<String, Vec<&crate::api::Finding>>> = BTreeMap::new();

    for finding in findings {
        let sev_key = severity_order(&finding.severity);
        grouped
            .entry(sev_key)
            .or_default()
            .entry(finding.rule_id.clone())
            .or_default()
            .push(*finding);
    }

    // Build a numbered rule index
    let mut rule_index: Vec<String> = Vec::new();
    for (_, rules_by_id) in &grouped {
        for (rule_id, _) in rules_by_id {
            if !rule_index.contains(rule_id) {
                rule_index.push(rule_id.clone());
            }
        }
    }

    // Display findings grouped by severity
    let mut first_severity = true;
    for (sev_key, rules_by_id) in &grouped {
        // Add blank line between severity groups (but not before the first one)
        if !first_severity {
            println!();
        }
        first_severity = false;

        let severity_name = match sev_key {
            0 => "Critical",
            1 => "High",
            2 => "Medium",
            3 => "Low",
            _ => "Other",
        };

        let severity_icon = match sev_key {
            0 => "🔴",
            1 => "🟠",
            2 => "🟡",
            3 => "🔵",
            _ => "⚪",
        };

        let severity_color = match sev_key {
            0 | 1 => "red",
            2 => "yellow",
            3 => "blue",
            _ => "white",
        };

        // Count total findings for this severity
        let severity_count: usize = rules_by_id.values().map(|v| v.len()).sum();
        println!(
            "{} {} ({} issue{})",
            severity_icon,
            severity_name.color(severity_color).bold(),
            severity_count,
            if severity_count == 1 { "" } else { "s" }
        );

        for (rule_id, rule_findings) in rules_by_id {
            let count = rule_findings.len();
            let title = &rule_findings[0].title;

            println!(
                "   [{}] {} ({}x)",
                rule_id.dimmed(),
                title,
                count.to_string().color("yellow")
            );
        }
    }
}

/// Display a single finding (for full mode)
fn display_finding(finding: &crate::api::Finding) {
    let severity_color = match finding.severity.as_str() {
        "Critical" => "red",
        "High" => "red",
        "Medium" => "yellow",
        "Low" => "blue",
        _ => "white",
    };

    let severity_icon = match finding.severity.as_str() {
        "Critical" => "🔴",
        "High" => "🟠",
        "Medium" => "🟡",
        "Low" => "🔵",
        _ => "⚪",
    };

    println!(
        "{} {} [{}]",
        severity_icon,
        finding.title.bold(),
        finding.severity.color(severity_color)
    );

    println!("   {}", finding.description.dimmed());
    println!(
        "   Rule: {} | Dimension: {} | Confidence: {:.0}%",
        finding.rule_id.cyan(),
        finding.dimension,
        finding.confidence * 100.0
    );

    if let Some(diff) = &finding.diff {
        println!();
        println!("   {}", "Suggested fix:".green().bold());
        for line in diff.lines() {
            if line.starts_with('+') && !line.starts_with("+++") {
                println!("   {}", line.green());
            } else if line.starts_with('-') && !line.starts_with("---") {
                println!("   {}", line.red());
            } else {
                println!("   {}", line.dimmed());
            }
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::WorkspaceScanner;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_workspace_scanner_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.source_files.is_empty());
    }
    #[test]
    fn test_workspace_scanner_python_files() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("main.py");
        fs::write(&file_path, "print('hello')").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert_eq!(info.source_files.len(), 1);
    }
    #[test]
    fn test_workspace_scanner_fastapi_detection() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("app.py");
        fs::write(&file_path, "from fastapi import FastAPI\napp = FastAPI()").unwrap();

        let mut scanner = WorkspaceScanner::new(temp_dir.path());
        let info = scanner.scan().unwrap();

        assert!(info.frameworks.iter().any(|f| f.name == "fastapi"));
    }
    #[test]
    fn test_display_finding_does_not_panic() {
        let finding = crate::api::Finding {
            id: "test_001".to_string(),
            rule_id: "test.rule".to_string(),
            kind: "BehaviorThreat".to_string(),
            title: "Test Finding".to_string(),
            description: "This is a test finding".to_string(),
            severity: "Medium".to_string(),
            confidence: 0.85,
            dimension: "Stability".to_string(),
            diff: None,
            fix_preview: None,
        };
        display_finding(&finding);
    }

    #[test]
    fn test_display_findings_grouped_does_not_panic() {
        let findings = vec![
            crate::api::Finding {
                id: "test_001".to_string(),
                rule_id: "http.timeout".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Missing HTTP timeout".to_string(),
                description: "HTTP call without timeout".to_string(),
                severity: "High".to_string(),
                confidence: 0.9,
                dimension: "Stability".to_string(),
                diff: None,
                fix_preview: None,
            },
            crate::api::Finding {
                id: "test_002".to_string(),
                rule_id: "http.timeout".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Missing HTTP timeout".to_string(),
                description: "Another HTTP call without timeout".to_string(),
                severity: "High".to_string(),
                confidence: 0.9,
                dimension: "Stability".to_string(),
                diff: None,
                fix_preview: None,
            },
            crate::api::Finding {
                id: "test_003".to_string(),
                rule_id: "cors.missing".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Missing CORS".to_string(),
                description: "No CORS configured".to_string(),
                severity: "Medium".to_string(),
                confidence: 0.85,
                dimension: "Correctness".to_string(),
                diff: None,
                fix_preview: None,
            },
            crate::api::Finding {
                id: "test_004".to_string(),
                rule_id: "critical.issue".to_string(),
                kind: "BehaviorThreat".to_string(),
                title: "Critical Issue".to_string(),
                description: "A critical issue".to_string(),
                severity: "Critical".to_string(),
                confidence: 0.95,
                dimension: "Stability".to_string(),
                diff: None,
                fix_preview: None,
            },
        ];
        let refs: Vec<&crate::api::Finding> = findings.iter().collect();
        display_findings_grouped(&refs);
    }

    #[test]
    fn test_display_findings_grouped_empty() {
        let findings: Vec<&crate::api::Finding> = vec![];
        display_findings_grouped(&findings);
    }
}

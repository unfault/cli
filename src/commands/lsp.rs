//! # LSP Server Command
//!
//! Implements the Language Server Protocol (LSP) server for IDE integration.
//! The LSP server provides real-time cognitive context by analyzing code using
//! the same client-side parsing approach as `unfault review`.
//!
//! ## Architecture
//!
//! The LSP server runs as a long-lived process communicating over stdio.
//! When documents are opened or changed:
//! 1. Parse the file locally using tree-sitter (via unfault-core)
//! 2. Build IR for the workspace (cached for performance)
//! 3. Send IR to the Unfault API for analysis
//! 4. Convert findings to LSP diagnostics with code actions
//!
//! ## Features
//!
//! - **Function Impact Hovers**: Hover over a function to see where it's used,
//!   which routes depend on it, and what safeguards exist in the call chain.
//! - **Real-time Diagnostics**: Inline insights about code behavior and patterns.
//! - **Quick Fixes**: Code actions to address missing safeguards.
//! - **File Centrality**: Status bar integration showing file importance.
//!
//! ## Project Root Detection
//!
//! When analyzing a file, the LSP server detects the appropriate project root
//! by walking up from the file's directory looking for project markers:
//! - `pyproject.toml`, `requirements.txt`, `setup.py` (Python)
//! - `package.json` (JavaScript/TypeScript)
//! - `Cargo.toml` (Rust)
//! - `go.mod` (Go)
//! - `pom.xml`, `build.gradle` (Java)
//! - `.git` directory (fallback)
//!
//! This allows proper analysis even when the IDE workspace is a monorepo.
//!
//! ## Custom Extensions
//!
//! The server supports custom LSP notifications:
//! - `unfault/fileCentrality`: Get file importance metrics for status bar display
//! - `unfault/fileDependencies`: Get list of files that depend on the current file
//!
//! ## Usage
//!
//! The server is typically launched by an IDE extension:
//!
//! ```bash
//! unfault lsp           # Start LSP server (stdio)
//! unfault lsp --verbose # Start with debug logging
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use log::debug;
use serde::{Deserialize, Serialize};
use tower_lsp::jsonrpc::Result as RpcResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::api::ApiClient;
use crate::api::graph::{
    CentralityRequest, FileCentrality, FunctionImpactRequest, FunctionInfo, ImpactAnalysisRequest,
    IrFinding,
};
use crate::config::Config;
use crate::exit_codes::*;
use crate::session::{
    WorkspaceScanner, build_ir_cached, compute_file_id, compute_workspace_id, get_git_remote,
};

// Import patch types from unfault-core for parsing patch_json
use unfault_core::IntermediateRepresentation;
use unfault_core::graph::GraphNode;
use unfault_core::types::{FilePatch, PatchRange};

/// Arguments for the LSP command
pub struct LspArgs {
    /// Enable verbose logging to stderr
    pub verbose: bool,
}

/// Cached finding with additional metadata for code actions
#[derive(Clone, Debug)]
struct CachedFinding {
    /// The original finding from analysis
    finding: IrFinding,
    /// Document version when this finding was created
    #[allow(dead_code)]
    version: i32,
}

/// File centrality response for custom notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCentralityNotification {
    /// File path (relative to workspace)
    pub path: String,
    /// Number of files that import this file
    pub in_degree: i32,
    /// Number of files this file imports
    pub out_degree: i32,
    /// Weighted importance score
    pub importance_score: i32,
    /// Total files in workspace
    pub total_files: i32,
    /// Human-readable label for status bar
    pub label: String,
}

/// File dependencies notification - list of files that depend on the current file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDependenciesNotification {
    /// File path being analyzed (relative to workspace)
    pub path: String,
    /// List of files that directly import this file
    pub direct_dependents: Vec<String>,
    /// List of all files affected (including transitive dependents)
    pub all_dependents: Vec<String>,
    /// Total count of affected files
    pub total_count: i32,
    /// Human-readable summary message
    pub summary: String,
}

/// Request for unfault/getFileCentrality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetFileCentralityRequest {
    /// Document URI
    pub uri: String,
}

/// Request for unfault/getFileDependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetFileDependenciesRequest {
    /// Document URI
    pub uri: String,
}

/// Request for unfault/refreshFile - triggers re-analysis of a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshFileRequest {
    /// Document URI
    pub uri: String,
}

/// Response for unfault/refreshFile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshFileResponse {
    /// Whether the refresh was successful
    pub success: bool,
    /// Number of findings after refresh
    pub finding_count: i32,
}

/// Caller information for function impact response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionImpactCaller {
    pub name: String,
    pub file: String,
    pub depth: i32,
    /// The function this caller calls (for call chain reconstruction)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls: Option<String>,
}

/// Route information for function impact response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionImpactRoute {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slos: Option<Vec<FunctionImpactSlo>>,
}

/// SLO information for function impact response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionImpactSlo {
    pub name: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_budget_remaining: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
}

/// Finding information for function impact response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionImpactFinding {
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "learnMore")]
    pub learn_more: Option<String>,
}

/// Summarized insight for function impact response
/// These are friendly, actionable summaries derived from raw findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionImpactInsight {
    pub severity: String,
    pub message: String,
}

/// Summarize raw findings into friendly, actionable insights
/// Groups findings by category and generates human-readable summaries
fn summarize_findings(findings: &[FunctionImpactFinding]) -> Vec<FunctionImpactInsight> {
    if findings.is_empty() {
        return Vec::new();
    }

    #[derive(Default)]
    struct Category {
        count: usize,
        severity: Option<String>,
    }

    let mut timeout = Category::default();
    let mut retry = Category::default();
    let mut logging = Category::default();
    let mut error_handling = Category::default();
    let mut security = Category::default();
    let mut other_messages: Vec<(String, String)> = Vec::new(); // (message, severity)

    for f in findings {
        let msg_lower = f.message.to_lowercase();
        
        if msg_lower.contains("timeout") {
            timeout.count += 1;
            if timeout.severity.is_none() || f.severity == "error" {
                timeout.severity = Some(f.severity.clone());
            }
        } else if msg_lower.contains("retry") || msg_lower.contains("retries") {
            retry.count += 1;
            if retry.severity.is_none() || f.severity == "error" {
                retry.severity = Some(f.severity.clone());
            }
        } else if msg_lower.contains("log") {
            logging.count += 1;
            if logging.severity.is_none() || f.severity == "error" {
                logging.severity = Some(f.severity.clone());
            }
        } else if msg_lower.contains("error") || msg_lower.contains("exception") || msg_lower.contains("handle") {
            error_handling.count += 1;
            if error_handling.severity.is_none() || f.severity == "error" {
                error_handling.severity = Some(f.severity.clone());
            }
        } else if msg_lower.contains("security") || msg_lower.contains("auth") || msg_lower.contains("injection") || msg_lower.contains("secret") {
            security.count += 1;
            if security.severity.is_none() || f.severity == "error" {
                security.severity = Some(f.severity.clone());
            }
        } else {
            other_messages.push((f.message.clone(), f.severity.clone()));
        }
    }

    let mut insights = Vec::new();

    // Generate friendly summaries for each category
    if timeout.count > 0 {
        insights.push(FunctionImpactInsight {
            severity: timeout.severity.unwrap_or_else(|| "warning".to_string()),
            message: "Missing timeout on external call".to_string(),
        });
    }
    if retry.count > 0 {
        insights.push(FunctionImpactInsight {
            severity: retry.severity.unwrap_or_else(|| "warning".to_string()),
            message: "No retry logic for transient failures".to_string(),
        });
    }
    if error_handling.count > 0 {
        insights.push(FunctionImpactInsight {
            severity: error_handling.severity.unwrap_or_else(|| "warning".to_string()),
            message: "Error handling could be improved".to_string(),
        });
    }
    if logging.count > 0 {
        insights.push(FunctionImpactInsight {
            severity: logging.severity.unwrap_or_else(|| "info".to_string()),
            message: "Could use better logging".to_string(),
        });
    }
    if security.count > 0 {
        insights.push(FunctionImpactInsight {
            severity: security.severity.unwrap_or_else(|| "error".to_string()),
            message: "Security concern flagged".to_string(),
        });
    }

    // Add first "other" message if we have room (max 3 insights)
    if insights.len() < 3 {
        if let Some((msg, sev)) = other_messages.into_iter().next() {
            // Clean up the message - take last part after colon, truncate if needed
            let cleaned = msg
                .rsplit(':')
                .next()
                .unwrap_or(&msg)
                .trim();
            let truncated = if cleaned.len() > 50 {
                format!("{}...", &cleaned[..47])
            } else {
                cleaned.to_string()
            };
            insights.push(FunctionImpactInsight {
                severity: sev,
                message: truncated,
            });
        }
    }

    // Return max 3 insights
    insights.truncate(3);
    insights
}

/// Request for unfault/getFunctionImpact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetFunctionImpactRequest {
    pub uri: String,
    #[serde(rename = "functionName")]
    pub function_name: String,
    pub position: Position,
}

/// Response for unfault/getFunctionImpact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetFunctionImpactResponse {
    pub name: String,
    pub callers: Vec<FunctionImpactCaller>,
    pub routes: Vec<FunctionImpactRoute>,
    /// Raw findings from analysis (for this function's file)
    pub findings: Vec<FunctionImpactFinding>,
    /// Friendly, summarized insights derived from findings (for this function)
    pub insights: Vec<FunctionImpactInsight>,
    /// Insights from callers in the call path (route handlers, etc.)
    #[serde(rename = "pathInsights")]
    pub path_insights: Vec<FunctionImpactInsight>,
}

fn normalize_severity(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error".to_string(),
        "medium" => "warning".to_string(),
        _ => "info".to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FindingSeverityThreshold {
    Critical,
    High,
    Medium,
    Low,
}

impl FindingSeverityThreshold {
    fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }

    fn from_finding_severity(severity: &str) -> Self {
        match severity.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspDiagnosticsSettings {
    enabled: bool,
    #[serde(default = "default_min_severity")]
    min_severity: FindingSeverityThreshold,
}

fn default_min_severity() -> FindingSeverityThreshold {
    FindingSeverityThreshold::High
}

impl Default for LspDiagnosticsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            min_severity: FindingSeverityThreshold::High,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LspClientSettings {
    #[serde(default)]
    diagnostics: LspDiagnosticsSettings,
}

fn apply_lsp_settings(current: &mut LspClientSettings, raw: &serde_json::Value) {
    let root = raw.get("unfault").unwrap_or(raw);
    let Some(diagnostics) = root.get("diagnostics") else {
        return;
    };

    if let Some(enabled) = diagnostics.get("enabled").and_then(|v| v.as_bool()) {
        current.diagnostics.enabled = enabled;
    }

    if let Some(min_severity) = diagnostics.get("minSeverity").and_then(|v| v.as_str()) {
        current.diagnostics.min_severity = match min_severity.to_lowercase().as_str() {
            "critical" => FindingSeverityThreshold::Critical,
            "high" => FindingSeverityThreshold::High,
            "medium" => FindingSeverityThreshold::Medium,
            "low" => FindingSeverityThreshold::Low,
            _ => current.diagnostics.min_severity,
        };
    }
}

/// The Unfault LSP backend
struct UnfaultLsp {
    /// LSP client for sending notifications
    client: Client,
    /// API client for calling Unfault API
    api_client: Arc<ApiClient>,
    /// Configuration (API key, etc.)
    config: Option<Config>,
    /// Workspace root path
    workspace_root: Arc<tokio::sync::RwLock<Option<PathBuf>>>,
    /// Workspace ID for API calls
    workspace_id: Arc<tokio::sync::RwLock<Option<String>>>,
    /// Cached session ID for incremental analysis (set after first full analysis)
    session_id: Arc<tokio::sync::RwLock<Option<String>>>,
    /// Cached findings for code actions, keyed by document URI
    findings_cache: DashMap<Url, Vec<CachedFinding>>,
    /// Cached document content for code actions, keyed by document URI
    /// Used to convert byte offsets to line/column positions when generating edits
    document_cache: scc::HashMap<Url, String>,
    /// Cached function info (name and range) for hover, keyed by document URI
    function_cache: DashMap<Url, Vec<FunctionInfo>>,
    /// Cached file centrality data for the workspace
    centrality_cache: Arc<tokio::sync::RwLock<Option<Vec<FileCentrality>>>>,
    /// Client-controlled display settings (diagnostics thresholds, etc.)
    settings: Arc<tokio::sync::RwLock<LspClientSettings>>,
    /// Enable verbose logging
    verbose: bool,
}

impl UnfaultLsp {
    fn new(client: Client, verbose: bool) -> Self {
        // Use the same base URL resolution as the rest of the CLI:
        // 1. UNFAULT_BASE_URL env var (if set)
        // 2. Config file's stored_base_url (if authenticated)
        // 3. Default production URL
        let config = crate::config::Config::load().ok();
        let api_url = config
            .as_ref()
            .map(|c| c.base_url())
            .unwrap_or_else(crate::config::default_base_url);

        if verbose {
            eprintln!("[unfault-lsp] API URL: {}", api_url);
            eprintln!("[unfault-lsp] Config loaded: {}", config.is_some());
        }

        let api_client = ApiClient::new(api_url);

        Self {
            client,
            api_client: Arc::new(api_client),
            config,
            workspace_root: Arc::new(tokio::sync::RwLock::new(None)),
            workspace_id: Arc::new(tokio::sync::RwLock::new(None)),
            session_id: Arc::new(tokio::sync::RwLock::new(None)),
            findings_cache: DashMap::new(),
            document_cache: scc::HashMap::new(),
            function_cache: DashMap::new(),
            centrality_cache: Arc::new(tokio::sync::RwLock::new(None)),
            settings: Arc::new(tokio::sync::RwLock::new(LspClientSettings::default())),
            verbose,
        }
    }

    /// Log a debug message if verbose mode is enabled
    fn log_debug(&self, message: &str) {
        if self.verbose {
            eprintln!("[unfault-lsp] {}", message);
        }
    }

    async fn republish_diagnostics_for_uri(&self, uri: &Url) {
        let settings = { self.settings.read().await.clone() };

        // If diagnostics are disabled, always clear.
        if !settings.diagnostics.enabled {
            self.client
                .publish_diagnostics(uri.clone(), vec![], None)
                .await;
            return;
        }

        let source_text = self
            .document_cache
            .get_async(uri)
            .await
            .map(|entry| entry.get().clone())
            .unwrap_or_default();

        let cached_findings = self.findings_cache.get(uri).map(|v| v.clone());
        let Some(cached_findings) = cached_findings else {
            self.client
                .publish_diagnostics(uri.clone(), vec![], None)
                .await;
            return;
        };

        let mut diagnostics = Vec::new();
        let mut version: Option<i32> = None;

        for cached in cached_findings.iter() {
            version = version
                .map(|v| v.max(cached.version))
                .or(Some(cached.version));

            let finding_severity =
                FindingSeverityThreshold::from_finding_severity(&cached.finding.severity);
            if finding_severity.rank() < settings.diagnostics.min_severity.rank() {
                continue;
            }

            diagnostics.push(self.finding_to_diagnostic(&cached.finding, &source_text));
        }

        self.client
            .publish_diagnostics(uri.clone(), diagnostics, version)
            .await;
    }

    async fn republish_diagnostics_for_open_documents(&self) {
        // Use findings_cache keys as our “open-ish” doc set.
        let uris: Vec<Url> = self
            .findings_cache
            .iter()
            .map(|e| e.key().clone())
            .collect();
        for uri in uris {
            self.republish_diagnostics_for_uri(&uri).await;
        }
    }

    /// Analyze a document and publish diagnostics
    ///
    /// # Arguments
    ///
    /// * `uri` - The document URI
    /// * `text` - The document content
    /// * `version` - Document version for diagnostics
    /// * `prebuilt_ir` - Optional pre-built IR to avoid rebuilding. If provided, skips the
    ///   `build_ir_cached` call which is expensive. Used by `did_open` to reuse the IR
    ///   already built for local dependency computation.
    async fn analyze_document(
        &self,
        uri: &Url,
        text: &str,
        version: i32,
        prebuilt_ir: Option<IntermediateRepresentation>,
    ) {
        self.log_debug(&format!("Analyzing document: {}", uri));

        // Get file path from URI
        let file_path = match uri.to_file_path() {
            Ok(path) => path,
            Err(_) => {
                self.log_debug("Could not convert URI to file path, skipping analysis");
                return;
            }
        };

        // Get IDE workspace root as fallback
        let ide_workspace_root = {
            let root = self.workspace_root.read().await;
            root.clone()
        };

        // Find the project root for this file by looking for project markers
        // This handles monorepo scenarios where the IDE workspace might be the monorepo root
        // but the file is in a subdirectory with its own project config
        let project_root = find_project_root(&file_path, ide_workspace_root.as_ref())
            .unwrap_or_else(|| {
                // Fall back to IDE workspace root if no project marker found
                ide_workspace_root
                    .clone()
                    .unwrap_or_else(|| file_path.parent().unwrap_or(&file_path).to_path_buf())
            });

        self.log_debug(&format!("Using project root: {:?}", project_root));

        // Get API key
        let api_key = match &self.config {
            Some(config) => config.api_key.clone(),
            None => {
                self.log_debug("No API key configured, skipping analysis");
                // Publish empty diagnostics to clear any stale ones
                self.client
                    .publish_diagnostics(uri.clone(), vec![], Some(version))
                    .await;
                return;
            }
        };

        // Use pre-built IR if provided, otherwise build it (with caching)
        // Pass content override for the current file to use buffer content instead of disk
        let (ir, should_send_dependencies) = match prebuilt_ir {
            Some(ir) => {
                self.log_debug("Using pre-built IR (skipping rebuild)");
                (ir, false) // Dependencies already sent by did_open
            }
            None => {
                // Create content override map with the current file's buffer content
                let mut content_overrides = std::collections::HashMap::new();
                content_overrides.insert(file_path.clone(), text.to_string());
                
                match build_ir_cached(&project_root, None, self.verbose, Some(&content_overrides)) {
                    Ok(result) => (result.ir, true), // Fresh IR, send dependencies
                    Err(e) => {
                        let msg = format!("Failed to build IR: {}", e);
                        self.log_debug(&msg);
                        self.client.show_message(MessageType::WARNING, msg).await;
                        return;
                    }
                }
            },
        };

        // Send dependencies notification when IR is rebuilt (on file change/save)
        if should_send_dependencies {
            let relative_path = file_path
                .strip_prefix(&project_root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            if !relative_path.is_empty() {
                if let Some(dependencies) = self.compute_local_dependencies(&ir, &relative_path) {
                    self.log_debug(&format!(
                        "Refreshing dependencies: {} direct, {} total for {}",
                        dependencies.direct_dependents.len(),
                        dependencies.total_count,
                        relative_path
                    ));
                    let _ = self
                        .client
                        .send_notification::<FileDependenciesNotificationType>(dependencies)
                        .await;
                }
            }
        }

        // Check if IR is too large (warn at 5MB, fail at 10MB)
        let ir_size = ir.semantics.len();
        if ir_size > 500 {
            self.log_debug(&format!("Large project: {} files", ir_size));
        }

        debug!("[LSP] === IR Statistics for Analysis ===");
        debug!("[LSP] Semantics count: {}", ir.semantics.len());
        let graph_stats = ir.graph.stats();
        debug!("[LSP] Graph file_count: {}", graph_stats.file_count);
        debug!("[LSP] Graph function_count: {}", graph_stats.function_count);
        debug!("[LSP] Graph class_count: {}", graph_stats.class_count);
        debug!(
            "[LSP] Graph external_module_count: {}",
            graph_stats.external_module_count
        );
        debug!(
            "[LSP] Graph import_edge_count: {}",
            graph_stats.import_edge_count
        );
        debug!(
            "[LSP] Graph contains_edge_count: {}",
            graph_stats.contains_edge_count
        );
        debug!(
            "[LSP] Graph uses_library_edge_count: {}",
            graph_stats.uses_library_edge_count
        );
        debug!(
            "[LSP] Graph calls_edge_count: {}",
            graph_stats.calls_edge_count
        );
        debug!("[LSP] Project root: {:?}", project_root);
        debug!("[LSP] File being analyzed: {:?}", file_path);

        // Compute workspace ID for this project
        let git_remote = get_git_remote(&project_root);
        let workspace_label = project_root
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());

        let workspace_id =
            compute_workspace_id(git_remote.as_deref(), None, workspace_label.as_deref())
                .map(|r| r.id)
                .unwrap_or_else(|| format!("wks_{}", uuid::Uuid::new_v4().simple()));

        debug!("[LSP] Workspace ID: {}", workspace_id);

        // Detect profiles from project
        let mut scanner = WorkspaceScanner::new(&project_root);
        let workspace_info = match scanner.scan() {
            Ok(info) => info,
            Err(e) => {
                let msg = format!("Failed to scan project: {}", e);
                self.log_debug(&msg);
                self.client.show_message(MessageType::WARNING, msg).await;
                return;
            }
        };

        let profiles: Vec<String> = workspace_info
            .to_workspace_descriptor()
            .profiles
            .iter()
            .map(|p| p.id.clone())
            .collect();

        debug!("[LSP] Profiles to use: {:?}", profiles);

        // Split IR so we can free the in-memory graph early
        let unfault_core::IntermediateRepresentation { semantics, graph } = ir;

        // Ingest full graph first
        let workspace_label_str = project_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("project");

        debug!("[LSP] Uploading graph for analysis (live session)...");
        let ingest = match self
            .api_client
            .ingest_graph(
                &api_key,
                &workspace_id,
                Some(workspace_label_str),
                git_remote.as_deref(),
                None, // TODO: Pass package_export for cross-workspace tracking
                graph,
                true, // is_live: reuse existing session for IDE real-time feedback
            )
            .await
        {
            Ok(resp) => {
                // Cache session_id for incremental single-file refreshes
                {
                    let mut session_cache = self.session_id.write().await;
                    *session_cache = Some(resp.session_id.clone());
                }
                resp
            }
            Err(e) => {
                debug!("[LSP] Graph ingest error: {:?}", e);
                let user_msg = match &e {
                    crate::api::ApiError::Unauthorized { .. } => {
                        "Analysis failed: Invalid or expired API key. Run 'unfault login' to re-authenticate.".to_string()
                    }
                    crate::api::ApiError::Server { status, .. } => {
                        format!("Analysis failed: Server error ({}). Please try again later.", status)
                    }
                    _ => format!("Analysis failed during graph upload: {:?}", e),
                };
                self.client
                    .show_message(MessageType::WARNING, user_msg)
                    .await;
                return;
            }
        };

        // Graph is moved into the ingestion request

        // Serialize semantics (smaller than full IR)
        let serialize_start = std::time::Instant::now();
        let semantics_json = match serde_json::to_string(&semantics) {
            Ok(json) => {
                debug!(
                    "[LSP] Semantics serialization time: {}ms",
                    serialize_start.elapsed().as_millis()
                );
                json
            }
            Err(e) => {
                let msg = format!("Failed to serialize semantics: {}", e);
                self.log_debug(&msg);
                self.client.show_message(MessageType::WARNING, msg).await;
                return;
            }
        };

        debug!("[LSP] Calling analyze_ir API (incremental)...");

        let response = match self
            .api_client
            .analyze_ir(
                &api_key,
                &ingest.session_id,
                &profiles,
                semantics_json,
                true, // incremental: delete old findings for these files before inserting new
            )
            .await
        {
            Ok(response) => response,
            Err(e) => {
                // Provide user-friendly error message
                debug!("[LSP] API error: {:?}", e);
                let user_msg = match &e {
                    crate::api::ApiError::Network { message } if message.contains("parse") => {
                        format!(
                            "Analysis failed: project may be too large ({} files). Try opening a smaller directory.",
                            ir_size
                        )
                    }
                    crate::api::ApiError::Unauthorized { .. } => {
                        "Analysis failed: Invalid or expired API key. Run 'unfault login' to re-authenticate.".to_string()
                    }
                    crate::api::ApiError::Server { status, .. } => {
                        format!("Analysis failed: Server error ({}). Please try again later.", status)
                    }
                    _ => format!("Analysis failed: {:?}", e),
                };
                self.log_debug(&format!("API error: {:?}", e));
                self.client
                    .show_message(MessageType::WARNING, user_msg)
                    .await;
                return;
            }
        };

        self.log_debug(&format!(
            "Analysis returned {} findings",
            response.findings.len()
        ));

        // Convert file path from absolute to relative to project root
        let relative_file_path = file_path
            .strip_prefix(&project_root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| file_path.to_string_lossy().to_string());

        // Filter findings for this document and (optionally) convert to diagnostics
        let settings = { self.settings.read().await.clone() };
        let mut diagnostics = Vec::new();
        let mut cached_findings = Vec::new();

        self.log_debug(&format!(
            "Looking for findings matching file: {}",
            relative_file_path
        ));

        for finding in &response.findings {
            // Check if this finding is for the current file
            // Compare using relative paths from the project root
            if !finding.file_path.ends_with(&relative_file_path)
                && !relative_file_path.ends_with(&finding.file_path)
            {
                continue;
            }

            // Cache for code actions / hovers (always)
            cached_findings.push(CachedFinding {
                finding: finding.clone(),
                version,
            });

            // Only publish diagnostics if enabled + within threshold
            if settings.diagnostics.enabled {
                let finding_severity =
                    FindingSeverityThreshold::from_finding_severity(&finding.severity);
                if finding_severity.rank() >= settings.diagnostics.min_severity.rank() {
                    diagnostics.push(self.finding_to_diagnostic(finding, text));
                }
            }
        }

        // Store cached findings (used for code actions/quick fixes)
        let finding_count = cached_findings.len() as i32;
        self.findings_cache.insert(uri.clone(), cached_findings);

        // Publish diagnostics (or clear them if disabled)
        let diagnostics_count = diagnostics.len();

        if settings.diagnostics.enabled {
            self.client
                .publish_diagnostics(uri.clone(), diagnostics, Some(version))
                .await;
        } else {
            self.client
                .publish_diagnostics(uri.clone(), vec![], Some(version))
                .await;
        }

        self.log_debug(&format!(
            "Diagnostics: enabled={} published={} for {}",
            settings.diagnostics.enabled, diagnostics_count, uri
        ));

        // Notify client that analysis is complete so it can refresh UI
        self.client
            .send_notification::<AnalysisCompleteNotificationType>(AnalysisCompleteNotification {
                uri: uri.to_string(),
                finding_count,
            })
            .await;
    }

    /// Convert a finding to an LSP diagnostic
    fn finding_to_diagnostic(&self, finding: &IrFinding, source_text: &str) -> Diagnostic {
        // Use finding's line/column if available, otherwise default to line 0
        let start_line = if finding.line > 0 {
            finding.line.saturating_sub(1)
        } else {
            0
        };
        let start_col = if finding.column > 0 {
            finding.column.saturating_sub(1)
        } else {
            0
        };
        let end_line = finding
            .end_line
            .map(|l| l.saturating_sub(1))
            .unwrap_or(start_line);
        let end_col = finding
            .end_column
            .map(|c| c.saturating_sub(1))
            .unwrap_or_else(|| {
                // If no end column, try to find the end of the line
                let lines: Vec<&str> = source_text.lines().collect();
                lines
                    .get(end_line as usize)
                    .map(|l| l.len() as u32)
                    .unwrap_or(start_col + 10)
            });

        let range = Range {
            start: Position {
                line: start_line,
                character: start_col,
            },
            end: Position {
                line: end_line,
                character: end_col,
            },
        };

        let severity = match finding.severity.to_lowercase().as_str() {
            "critical" | "high" => DiagnosticSeverity::ERROR,
            "medium" => DiagnosticSeverity::WARNING,
            "low" | "info" => DiagnosticSeverity::INFORMATION,
            _ => DiagnosticSeverity::WARNING,
        };

        let message = if finding.message.is_empty() {
            format!("{}: {}", finding.title, finding.description)
        } else {
            finding.message.clone()
        };

        Diagnostic {
            range,
            severity: Some(severity),
            code: Some(NumberOrString::String(finding.rule_id.clone())),
            code_description: Some(CodeDescription {
                href: Url::parse(&format!(
                    "https://docs.unfault.dev/rules/{}",
                    finding.rule_id.replace('.', "/")
                ))
                .unwrap_or_else(|_| Url::parse("https://unfault.dev").unwrap()),
            }),
            source: Some("unfault".to_string()),
            message,
            related_information: None,
            tags: None,
            data: Some(serde_json::json!({
                "rule_id": finding.rule_id,
                "dimension": finding.dimension,
                "has_fix": finding.patch.is_some() || finding.patch_json.is_some(),
            })),
        }
    }

    /// Get code actions for a given range
    fn get_code_actions_for_range(
        &self,
        uri: &Url,
        range: &Range,
        source_text: &str,
    ) -> Vec<CodeAction> {
        let mut actions = Vec::new();

        // Get cached findings for this document
        let findings = match self.findings_cache.get(uri) {
            Some(f) => f.clone(),
            None => return actions,
        };

        for cached in findings.iter() {
            let finding = &cached.finding;

            // Check if finding overlaps with requested range
            let finding_start = Position {
                line: finding.line.saturating_sub(1),
                character: finding.column.saturating_sub(1),
            };
            let finding_end = Position {
                line: finding.end_line.unwrap_or(finding.line).saturating_sub(1),
                character: finding
                    .end_column
                    .unwrap_or(finding.column + 10)
                    .saturating_sub(1),
            };

            let finding_range = Range {
                start: finding_start,
                end: finding_end,
            };

            // Check for overlap
            if !ranges_overlap(range, &finding_range) {
                continue;
            }

            // Create quick fix action if patch is available
            if let Some(patch) = &finding.patch {
                if let Some(edit) = self.parse_unified_diff(uri, patch, source_text) {
                    let action = CodeAction {
                        title: format!("Fix: {}", finding.title),
                        kind: Some(CodeActionKind::QUICKFIX),
                        diagnostics: Some(vec![self.finding_to_diagnostic(finding, source_text)]),
                        edit: Some(edit),
                        command: None,
                        is_preferred: Some(true),
                        disabled: None,
                        data: None,
                    };
                    actions.push(action);
                }
            }

            // Also check patch_json (newer format with structured hunks)
            if let Some(patch_json) = &finding.patch_json {
                // Use the structured patch for proper multi-hunk edits
                if let Some(edit) = self.create_edit_from_patch_json(uri, patch_json, source_text) {
                    let action = CodeAction {
                        title: format!("Fix: {}", finding.title),
                        kind: Some(CodeActionKind::QUICKFIX),
                        diagnostics: Some(vec![self.finding_to_diagnostic(finding, source_text)]),
                        edit: Some(edit),
                        command: None,
                        is_preferred: Some(true),
                        disabled: None,
                        data: None,
                    };
                    actions.push(action);
                } else if let Some(preview) = &finding.fix_preview {
                    // Fallback to fix_preview if patch_json parsing fails
                    if let Some(edit) =
                        self.create_edit_from_preview(uri, finding, preview, source_text)
                    {
                        let action = CodeAction {
                            title: format!("Fix: {}", finding.title),
                            kind: Some(CodeActionKind::QUICKFIX),
                            diagnostics: Some(vec![
                                self.finding_to_diagnostic(finding, source_text),
                            ]),
                            edit: Some(edit),
                            command: None,
                            is_preferred: Some(true),
                            disabled: None,
                            data: None,
                        };
                        actions.push(action);
                    }
                }
            }
        }

        actions
    }

    /// Parse a unified diff and create a workspace edit
    fn parse_unified_diff(
        &self,
        uri: &Url,
        diff: &str,
        source_text: &str,
    ) -> Option<WorkspaceEdit> {
        let mut text_edits = Vec::new();
        let lines: Vec<&str> = diff.lines().collect();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];

            // Parse hunk header: @@ -start,count +start,count @@
            if line.starts_with("@@") {
                if let Some(hunk) = parse_hunk_header(line) {
                    let (_old_start, new_content) = parse_hunk_content(&lines[i + 1..]);

                    // Create edit for this hunk
                    // old_start is 1-indexed, convert to 0-indexed
                    let start_line = hunk.old_start.saturating_sub(1);
                    let end_line = start_line + hunk.old_count;

                    // Find the character positions
                    let source_lines: Vec<&str> = source_text.lines().collect();
                    let end_char = source_lines
                        .get(end_line as usize)
                        .map(|l| l.len() as u32)
                        .unwrap_or(0);

                    let edit = TextEdit {
                        range: Range {
                            start: Position {
                                line: start_line,
                                character: 0,
                            },
                            end: Position {
                                line: end_line,
                                character: end_char,
                            },
                        },
                        new_text: new_content,
                    };
                    text_edits.push(edit);
                }
            }
            i += 1;
        }

        if text_edits.is_empty() {
            return None;
        }

        let mut changes = HashMap::new();
        changes.insert(uri.clone(), text_edits);

        Some(WorkspaceEdit {
            changes: Some(changes),
            document_changes: None,
            change_annotations: None,
        })
    }

    /// Create a workspace edit from patch_json (structured patch with multiple hunks)
    ///
    /// The patch_json contains a FilePatch with hunks that specify exact locations
    /// for each edit (e.g., import insertion at one line, middleware at another).
    fn create_edit_from_patch_json(
        &self,
        uri: &Url,
        patch_json: &str,
        source_text: &str,
    ) -> Option<WorkspaceEdit> {
        // Parse the FilePatch from JSON
        let patch: FilePatch = match serde_json::from_str(patch_json) {
            Ok(p) => p,
            Err(e) => {
                self.log_debug(&format!("Failed to parse patch_json: {}", e));
                return None;
            }
        };

        if patch.hunks.is_empty() {
            return None;
        }

        // Precompute line start byte offsets (needed for InsertAfterLine)
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(
                source_text
                    .char_indices()
                    .filter_map(|(idx, ch)| if ch == '\n' { Some(idx + 1) } else { None }),
            )
            .chain(std::iter::once(source_text.len()))
            .collect();

        let source_lines: Vec<&str> = source_text.lines().collect();
        let mut text_edits = Vec::new();

        for hunk in &patch.hunks {
            match &hunk.range {
                PatchRange::InsertAfterLine { line } => {
                    // line is 1-based; line == 0 means insert at the very beginning
                    if *line == 0 {
                        // Insert at the very beginning of the file
                        let edit = TextEdit {
                            range: Range {
                                start: Position {
                                    line: 0,
                                    character: 0,
                                },
                                end: Position {
                                    line: 0,
                                    character: 0,
                                },
                            },
                            new_text: hunk.replacement.clone(),
                        };
                        text_edits.push(edit);
                    } else {
                        // Insert after the specified line
                        // LSP lines are 0-indexed, so line N (1-indexed) becomes line N-1 (0-indexed)
                        // We want to insert at the START of the next line (line N 0-indexed)
                        let target_line = *line;
                        let edit = TextEdit {
                            range: Range {
                                start: Position {
                                    line: target_line,
                                    character: 0,
                                },
                                end: Position {
                                    line: target_line,
                                    character: 0,
                                },
                            },
                            new_text: hunk.replacement.clone(),
                        };
                        text_edits.push(edit);
                    }
                }
                PatchRange::InsertBeforeLine { line } => {
                    // line is 1-based; insert before line N means insert at start of line N-1 (0-indexed)
                    let target_line = line.saturating_sub(1);
                    let edit = TextEdit {
                        range: Range {
                            start: Position {
                                line: target_line,
                                character: 0,
                            },
                            end: Position {
                                line: target_line,
                                character: 0,
                            },
                        },
                        new_text: hunk.replacement.clone(),
                    };
                    text_edits.push(edit);
                }
                PatchRange::InsertAt { byte_offset } => {
                    // Convert byte offset to line/column
                    if let Some((line, col)) =
                        byte_offset_to_position(&line_starts, &source_lines, *byte_offset)
                    {
                        let edit = TextEdit {
                            range: Range {
                                start: Position {
                                    line: line as u32,
                                    character: col as u32,
                                },
                                end: Position {
                                    line: line as u32,
                                    character: col as u32,
                                },
                            },
                            new_text: hunk.replacement.clone(),
                        };
                        text_edits.push(edit);
                    }
                }
                PatchRange::ReplaceBytes { start, end } => {
                    // Convert byte range to line/column positions
                    if let (Some((start_line, start_col)), Some((end_line, end_col))) = (
                        byte_offset_to_position(&line_starts, &source_lines, *start),
                        byte_offset_to_position(&line_starts, &source_lines, *end),
                    ) {
                        let edit = TextEdit {
                            range: Range {
                                start: Position {
                                    line: start_line as u32,
                                    character: start_col as u32,
                                },
                                end: Position {
                                    line: end_line as u32,
                                    character: end_col as u32,
                                },
                            },
                            new_text: hunk.replacement.clone(),
                        };
                        text_edits.push(edit);
                    }
                }
            }
        }

        if text_edits.is_empty() {
            return None;
        }

        let mut changes = HashMap::new();
        changes.insert(uri.clone(), text_edits);

        Some(WorkspaceEdit {
            changes: Some(changes),
            document_changes: None,
            change_annotations: None,
        })
    }

    /// Create a workspace edit from a fix preview (fallback when no patch_json)
    fn create_edit_from_preview(
        &self,
        uri: &Url,
        finding: &IrFinding,
        preview: &str,
        _source_text: &str,
    ) -> Option<WorkspaceEdit> {
        // The preview is the replacement text for the finding range
        let start_line = finding.line.saturating_sub(1);
        let start_col = finding.column.saturating_sub(1);
        let end_line = finding.end_line.unwrap_or(finding.line).saturating_sub(1);
        let end_col = finding
            .end_column
            .unwrap_or(finding.column + 10)
            .saturating_sub(1);

        let edit = TextEdit {
            range: Range {
                start: Position {
                    line: start_line,
                    character: start_col,
                },
                end: Position {
                    line: end_line,
                    character: end_col,
                },
            },
            new_text: preview.to_string(),
        };

        let mut changes = HashMap::new();
        changes.insert(uri.clone(), vec![edit]);

        Some(WorkspaceEdit {
            changes: Some(changes),
            document_changes: None,
            change_annotations: None,
        })
    }

    /// Get file centrality for a given file path
    async fn get_file_centrality(&self, file_path: &str) -> Option<FileCentralityNotification> {
        let api_key = self.config.as_ref()?.api_key.clone();
        let workspace_id = self.workspace_id.read().await.clone()?;

        // Check cache first
        {
            let cache = self.centrality_cache.read().await;
            if let Some(centralities) = cache.as_ref() {
                if let Some(centrality) = centralities
                    .iter()
                    .find(|c| c.path.ends_with(file_path) || file_path.ends_with(&c.path))
                {
                    let total_files = centralities.len() as i32;
                    return Some(self.centrality_to_notification(centrality, total_files));
                }
            }
        }

        // Fetch from API
        let request = CentralityRequest {
            session_id: None,
            workspace_id: Some(workspace_id),
            limit: 50, // Get top 50 files
            sort_by: "in_degree".to_string(),
        };

        let response = match self.api_client.graph_centrality(&api_key, &request).await {
            Ok(r) => r,
            Err(e) => {
                self.log_debug(&format!("Failed to fetch centrality: {:?}", e));
                return None;
            }
        };

        // Update cache
        {
            let mut cache = self.centrality_cache.write().await;
            *cache = Some(response.files.clone());
        }

        // Find the file in the response
        response
            .files
            .iter()
            .find(|c| c.path.ends_with(file_path) || file_path.ends_with(&c.path))
            .map(|c| self.centrality_to_notification(c, response.total_files))
    }

    /// Convert FileCentrality to notification format with human-readable label
    fn centrality_to_notification(
        &self,
        centrality: &FileCentrality,
        total_files: i32,
    ) -> FileCentralityNotification {
        // Generate a human-readable label for the status bar
        let label = if centrality.in_degree > 10 {
            format!("Hub file ({} importers)", centrality.in_degree)
        } else if centrality.in_degree > 5 {
            format!("Important file ({} importers)", centrality.in_degree)
        } else if centrality.in_degree > 0 {
            format!("{} importers", centrality.in_degree)
        } else if centrality.out_degree > 5 {
            format!("Leaf file ({} imports)", centrality.out_degree)
        } else {
            "Leaf file".to_string()
        };

        FileCentralityNotification {
            path: centrality.path.clone(),
            in_degree: centrality.in_degree,
            out_degree: centrality.out_degree,
            importance_score: centrality.importance_score,
            total_files,
            label,
        }
    }

    /// Get files that depend on a given file using the impact analysis API
    ///
    /// Note: This method is currently unused as we prefer computing dependencies
    /// locally from the IR graph (compute_local_dependencies). It's kept for
    /// potential future use when API-based dependency data is needed.
    #[allow(dead_code)]
    async fn get_file_dependencies(&self, file_path: &str) -> Option<FileDependenciesNotification> {
        let api_key = self.config.as_ref()?.api_key.clone();
        let workspace_id = self.workspace_id.read().await.clone()?;

        self.log_debug(&format!("Fetching dependencies for: {}", file_path));

        // Call impact analysis API
        let request = ImpactAnalysisRequest {
            session_id: None,
            workspace_id: Some(workspace_id),
            file_path: file_path.to_string(),
            max_depth: 3, // Limit depth for performance
        };

        let response = match self.api_client.graph_impact(&api_key, &request).await {
            Ok(r) => r,
            Err(e) => {
                self.log_debug(&format!("Failed to fetch dependencies: {:?}", e));
                return None;
            }
        };

        let direct_count = response.direct_importers.len();
        let total_count = response.total_affected;

        // Generate human-readable summary
        let summary = if total_count == 0 {
            "No other files depend on this file".to_string()
        } else if direct_count == 1 && total_count == 1 {
            format!(
                "1 file depends on this file: {}",
                response.direct_importers[0].path
            )
        } else if direct_count == total_count as usize {
            format!("{} files depend on this file", total_count)
        } else {
            format!(
                "{} files directly import this file ({} total affected)",
                direct_count, total_count
            )
        };

        Some(FileDependenciesNotification {
            path: file_path.to_string(),
            direct_dependents: response
                .direct_importers
                .iter()
                .map(|f| f.path.clone())
                .collect(),
            all_dependents: response
                .transitive_importers
                .iter()
                .map(|f| f.path.clone())
                .collect(),
            total_count,
            summary,
        })
    }

    /// Compute file dependencies directly from the local IR graph.
    ///
    /// This method extracts dependency information from the locally-built IR graph
    /// without needing to query the API. This is essential for showing dependencies
    /// immediately when a project is first opened, before any API session exists.
    ///
    /// # Arguments
    ///
    /// * `ir` - The IntermediateRepresentation containing the code graph
    /// * `file_path` - Relative path to the file being analyzed
    ///
    /// # Returns
    ///
    /// A `FileDependenciesNotification` with all files that import the given file.
    fn compute_local_dependencies(
        &self,
        ir: &IntermediateRepresentation,
        file_path: &str,
    ) -> Option<FileDependenciesNotification> {
        let graph = &ir.graph;

        debug!("[LSP] === Computing Local Dependencies ===");
        debug!("[LSP] Looking for file: {}", file_path);
        debug!("[LSP] Graph has {} files", graph.stats().file_count);

        // Find the file node by path
        let file_idx = graph.find_file_by_path(file_path)?;

        // Get the file_id from the node
        let file_id = match &graph.graph[file_idx] {
            GraphNode::File { file_id, .. } => *file_id,
            _ => {
                debug!("[LSP] Node is not a File node, skipping");
                return None;
            }
        };

        debug!("[LSP] File ID: {:?}", file_id);

        // Get direct importers
        let direct_importer_ids = graph.get_importers(file_id);
        debug!("[LSP] Direct importer IDs: {:?}", direct_importer_ids);

        // Convert FileIds to paths
        let direct_dependents: Vec<String> = direct_importer_ids
            .iter()
            .filter_map(|&fid| {
                let idx = graph.file_nodes.get(&fid)?;
                if let GraphNode::File { path, .. } = &graph.graph[*idx] {
                    Some(path.clone())
                } else {
                    None
                }
            })
            .collect();

        debug!("[LSP] Direct dependent files: {:?}", direct_dependents);

        // Get transitive importers (up to depth 3 for consistency with API)
        let transitive = graph.get_transitive_importers(file_id, 3);
        debug!(
            "[LSP] Transitive importers (depth 3): {} entries",
            transitive.len()
        );
        let all_dependents: Vec<String> = transitive
            .iter()
            .filter_map(|&(fid, _depth)| {
                let idx = graph.file_nodes.get(&fid)?;
                if let GraphNode::File { path, .. } = &graph.graph[*idx] {
                    Some(path.clone())
                } else {
                    None
                }
            })
            .collect();

        debug!(
            "[LSP] All dependent files (including transitive): {:?}",
            all_dependents
        );

        let direct_count = direct_dependents.len();
        let total_count = all_dependents.len() as i32;

        // Generate human-readable summary
        let summary = if total_count == 0 {
            "No other files depend on this file".to_string()
        } else if direct_count == 1 && total_count == 1 {
            format!("1 file depends on this file: {}", direct_dependents[0])
        } else if direct_count == total_count as usize {
            format!("{} files depend on this file", total_count)
        } else {
            format!(
                "{} files directly import this file ({} total affected)",
                direct_count, total_count
            )
        };

        debug!("[LSP] Dependency summary: {}", summary);
        debug!(
            "[LSP] Direct dependents: {}, Total affected: {}",
            direct_count, total_count
        );

        self.log_debug(&format!(
            "Local graph: {} direct dependents, {} total for {}",
            direct_count, total_count, file_path
        ));

        Some(FileDependenciesNotification {
            path: file_path.to_string(),
            direct_dependents,
            all_dependents,
            total_count,
            summary,
        })
    }

    /// Extract function info from IR semantics for a specific file.
    ///
    /// This extracts function names and their ranges from the language-specific
    /// semantics stored in the IR, allowing the LSP to provide hover info
    /// about functions being edited.
    fn extract_functions_from_ir(
        &self,
        ir: &IntermediateRepresentation,
        file_path: &str,
    ) -> Vec<FunctionInfo> {
        use unfault_core::semantics::SourceSemantics;

        let mut functions = Vec::new();

        // Find the semantics for this file
        for sem in &ir.semantics {
            if sem.file_path() != file_path {
                continue;
            }

            match sem {
                SourceSemantics::Python(py_sem) => {
                    for func in &py_sem.functions {
                        let range = Range {
                            start: Position {
                                line: func.location.range.start_line,
                                character: func.location.range.start_col,
                            },
                            end: Position {
                                line: func.location.range.end_line,
                                character: func.location.range.end_col,
                            },
                        };
                        // Build qualified name: Class.method for methods, just name for functions
                        let qualified_name = match &func.class_name {
                            Some(class) => format!("{}.{}", class, func.name),
                            None => func.name.clone(),
                        };
                        functions.push(FunctionInfo {
                            name: qualified_name,
                            range,
                        });
                    }
                }
                SourceSemantics::Go(go_sem) => {
                    // Go top-level functions (no receiver)
                    for func in &go_sem.functions {
                        let range = Range {
                            start: Position {
                                line: func.location.range.start_line,
                                character: func.location.range.start_col,
                            },
                            end: Position {
                                line: func.location.range.end_line,
                                character: func.location.range.end_col,
                            },
                        };
                        functions.push(FunctionInfo {
                            name: func.name.clone(),
                            range,
                        });
                    }
                    // Go methods - build qualified name: ReceiverType.methodName
                    for method in &go_sem.methods {
                        let range = Range {
                            start: Position {
                                line: method.location.range.start_line,
                                character: method.location.range.start_col,
                            },
                            end: Position {
                                line: method.location.range.end_line,
                                character: method.location.range.end_col,
                            },
                        };
                        let qualified_name = format!("{}.{}", method.receiver_type, method.name);
                        functions.push(FunctionInfo {
                            name: qualified_name,
                            range,
                        });
                    }
                }
                SourceSemantics::Typescript(ts_sem) => {
                    // Top-level functions
                    for func in &ts_sem.functions {
                        let range = Range {
                            start: Position {
                                line: func.location.range.start_line,
                                character: func.location.range.start_col,
                            },
                            end: Position {
                                line: func.location.range.end_line,
                                character: func.location.range.end_col,
                            },
                        };
                        functions.push(FunctionInfo {
                            name: func.name.clone(),
                            range,
                        });
                    }
                    // Class methods - build qualified name: ClassName.methodName
                    for class in &ts_sem.classes {
                        for method in &class.methods {
                            let range = Range {
                                start: Position {
                                    line: method.location.range.start_line,
                                    character: method.location.range.start_col,
                                },
                                end: Position {
                                    line: method.location.range.end_line,
                                    character: method.location.range.end_col,
                                },
                            };
                            let qualified_name = format!("{}.{}", class.name, method.name);
                            functions.push(FunctionInfo {
                                name: qualified_name,
                                range,
                            });
                        }
                    }
                }
                SourceSemantics::Rust(rust_sem) => {
                    // Top-level functions
                    for func in &rust_sem.functions {
                        let range = Range {
                            start: Position {
                                line: func.location.range.start_line,
                                character: func.location.range.start_col,
                            },
                            end: Position {
                                line: func.location.range.end_line,
                                character: func.location.range.end_col,
                            },
                        };
                        functions.push(FunctionInfo {
                            name: func.name.clone(),
                            range,
                        });
                    }
                    // Impl block methods - build qualified name: SelfType.methodName
                    for impl_block in &rust_sem.impls {
                        for method in &impl_block.methods {
                            let range = Range {
                                start: Position {
                                    line: method.location.range.start_line,
                                    character: method.location.range.start_col,
                                },
                                end: Position {
                                    line: method.location.range.end_line,
                                    character: method.location.range.end_col,
                                },
                            };
                            let qualified_name =
                                format!("{}.{}", impl_block.self_type, method.name);
                            functions.push(FunctionInfo {
                                name: qualified_name,
                                range,
                            });
                        }
                    }
                }
            }
        }

        functions
    }

    /// Get the function name at a given position in a document
    async fn get_function_at_position(&self, uri: &Url, position: Position) -> Option<String> {
        // Get cached functions for this document
        let functions = match self.function_cache.get(uri) {
            Some(f) => f.clone(),
            None => return None,
        };

        // Find the function whose range contains the position
        for func in functions.iter() {
            if position.line >= func.range.start.line
                && position.line <= func.range.end.line
                && (position.line > func.range.start.line
                    || position.character >= func.range.start.character)
                && (position.line < func.range.end.line
                    || position.character <= func.range.end.character)
            {
                return Some(func.name.clone());
            }
        }

        None
    }

    /// Get function impact analysis as a markdown hover string
    ///
    /// Returns a formatted markdown string showing:
    /// - Function callers (direct and transitive)
    /// - Routes that use this function
    /// - Safeguards present (or missing) in the call chain
    /// - Code review findings for the function
    async fn get_function_impact(
        &self,
        file_path: &str,
        function_name: &str,
        start_line: Option<i32>,
        end_line: Option<i32>,
    ) -> Option<String> {
        let api_key = self.config.as_ref()?.api_key.clone();
        let workspace_id = self.workspace_id.read().await.clone()?;

        self.log_debug(&format!(
            "Fetching impact for function: {} in {} (lines {:?}-{:?})",
            function_name, file_path, start_line, end_line
        ));

        // Call function impact API
        // The API will resolve workspace_id to the live session if one exists
        let workspace_root = { self.workspace_root.read().await.clone() };
        let git_remote = workspace_root.as_ref().and_then(|p| get_git_remote(p));
        let file_id = Some(compute_file_id(
            git_remote.as_deref(),
            &workspace_id,
            file_path,
        ));

        let request = FunctionImpactRequest {
            session_id: None,
            workspace_id: Some(workspace_id),
            file_id,
            file_path: file_path.to_string(),
            function_name: function_name.to_string(),
            start_line,
            end_line,
            max_depth: 5,
        };

        let response = match self
            .api_client
            .graph_function_impact(&api_key, &request)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.log_debug(&format!("Failed to fetch function impact: {:?}", e));
                return None;
            }
        };

        // Format as markdown
        let mut markdown = String::new();
        markdown.push_str(&format!("**Function Impact:** {}\n\n", response.function));

        // Show impact summary if available
        if !response.impact_summary.is_empty() {
            markdown.push_str(&format!("{}\n\n", response.impact_summary));
        }

        markdown.push_str(&format!(
            "Total affected functions: {}\n\n",
            response.total_affected
        ));

        // Collect route handlers from both direct and transitive callers
        // Only include handlers that have actual route info (non-empty method or path)
        let all_callers: Vec<_> = response
            .direct_callers
            .iter()
            .chain(response.transitive_callers.iter())
            .filter(|c| c.is_route_handler)
            .filter(|c| c.route_method.is_some() || c.route_path.is_some())
            .collect();

        // Deduplicate route handlers by (method, path)
        let mut seen_routes = std::collections::HashSet::new();
        let unique_route_handlers: Vec<_> = all_callers
            .iter()
            .filter(|c| {
                let key = (
                    c.route_method.as_deref().unwrap_or(""),
                    c.route_path.as_deref().unwrap_or(""),
                );
                if seen_routes.contains(&key) {
                    false
                } else {
                    seen_routes.insert(key);
                    true
                }
            })
            .collect();

        if !unique_route_handlers.is_empty() {
            markdown.push_str("**HTTP Route Handlers:**\n");
            for handler in unique_route_handlers {
                let method = handler.route_method.as_deref().unwrap_or("").to_uppercase();
                let path = handler.route_path.as_deref().unwrap_or("");
                let depth = if handler.depth > 1 {
                    format!(" (via {} hops)", handler.depth)
                } else {
                    String::new()
                };
                markdown.push_str(&format!(
                    "- `{} {}` → {}{}\n",
                    method, path, handler.function, depth
                ));
            }
            markdown.push('\n');
        }

        // Show all callers (direct first, then transitive if any)
        let all_non_route_callers: Vec<_> = response
            .direct_callers
            .iter()
            .chain(response.transitive_callers.iter())
            .filter(|c| !c.is_route_handler)
            .collect();

        if !all_non_route_callers.is_empty() {
            markdown.push_str("**Call Chain:**\n");
            for caller in all_non_route_callers {
                let depth_label = if caller.depth > 1 {
                    format!(" (depth {})", caller.depth)
                } else {
                    String::new()
                };
                markdown.push_str(&format!("- {}{}\n", caller.function, depth_label));
            }
            markdown.push('\n');
        }

        // Show code review findings for this function
        if !response.findings.is_empty() {
            markdown.push_str("**Code Review Insights:**\n");
            for finding in &response.findings {
                let icon = match finding.severity.to_lowercase().as_str() {
                    "critical" | "high" => "💡",
                    "medium" => "✨",
                    "low" | "info" => "✓",
                    _ => "○",
                };
                markdown.push_str(&format!(
                    "- {} **{}** ({})\n  {}\n",
                    icon,
                    finding.title,
                    finding.dimension,
                    finding.description.lines().next().unwrap_or("")
                ));
            }
            markdown.push('\n');
        }

        Some(markdown)
    }
}

/// Convert a byte offset to (line, column) tuple
/// Returns None if the offset is out of bounds
fn byte_offset_to_position(
    line_starts: &[usize],
    source_lines: &[&str],
    offset: usize,
) -> Option<(usize, usize)> {
    // Find the line containing this offset using binary search
    let line_idx = match line_starts.binary_search(&offset) {
        Ok(idx) => idx,                    // Exact match - start of a line
        Err(idx) => idx.saturating_sub(1), // In the middle of a line
    };

    if line_idx >= source_lines.len() {
        // Handle offset at or past EOF
        if offset >= *line_starts.last().unwrap_or(&0) {
            return Some((
                source_lines.len().saturating_sub(1),
                source_lines.last().map(|l| l.len()).unwrap_or(0),
            ));
        }
        return None;
    }

    let line_start = line_starts[line_idx];
    let col = offset.saturating_sub(line_start);

    // Validate column is within line bounds
    let line_len = source_lines.get(line_idx).map(|l| l.len()).unwrap_or(0);
    let col = col.min(line_len);

    Some((line_idx, col))
}

/// Check if two ranges overlap
fn ranges_overlap(a: &Range, b: &Range) -> bool {
    !(a.end.line < b.start.line
        || (a.end.line == b.start.line && a.end.character < b.start.character)
        || b.end.line < a.start.line
        || (b.end.line == a.start.line && b.end.character < a.start.character))
}

/// Project marker files that indicate a project root
const PROJECT_MARKERS: &[&str] = &[
    // Python
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    // JavaScript/TypeScript
    "package.json",
    // Rust
    "Cargo.toml",
    // Go
    "go.mod",
    // Java
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    // Unfault config
    ".unfault.toml",
    "unfault.toml",
];

/// Find the project root for a given file by walking up the directory tree
/// looking for project marker files.
///
/// This handles monorepo scenarios where the IDE workspace might be the monorepo root
/// but files are in subdirectories with their own project configuration.
///
/// # Arguments
///
/// * `file_path` - The path to the file being analyzed
/// * `ide_workspace_root` - The IDE workspace root (used as an upper bound for the search)
///
/// # Returns
///
/// The project root if found, or None if no project marker was found.
fn find_project_root(file_path: &Path, ide_workspace_root: Option<&PathBuf>) -> Option<PathBuf> {
    // Start from the file's parent directory
    let mut current = file_path.parent()?;

    // Don't search beyond the IDE workspace root if provided
    let stop_at = ide_workspace_root.map(|p| p.as_path());

    loop {
        // Check if this directory contains any project marker
        for marker in PROJECT_MARKERS {
            let marker_path = current.join(marker);
            if marker_path.exists() {
                return Some(current.to_path_buf());
            }
        }

        // Also check for .git as a fallback project boundary
        let git_path = current.join(".git");
        if git_path.exists() {
            return Some(current.to_path_buf());
        }

        // Stop if we've reached the IDE workspace root
        if let Some(stop) = stop_at {
            if current == stop {
                break;
            }
        }

        // Move up to the parent directory
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    None
}

/// Parsed hunk header information
#[allow(dead_code)]
struct HunkHeader {
    old_start: u32,
    old_count: u32,
    new_start: u32,
    new_count: u32,
}

/// Parse a hunk header like "@@ -1,3 +1,4 @@"
fn parse_hunk_header(line: &str) -> Option<HunkHeader> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let old_part = parts[1].trim_start_matches('-');
    let new_part = parts[2].trim_start_matches('+');

    let (old_start, old_count) = parse_range_spec(old_part)?;
    let (new_start, new_count) = parse_range_spec(new_part)?;

    Some(HunkHeader {
        old_start,
        old_count,
        new_start,
        new_count,
    })
}

/// Parse a range spec like "1,3" or "1"
fn parse_range_spec(spec: &str) -> Option<(u32, u32)> {
    if let Some((start, count)) = spec.split_once(',') {
        Some((start.parse().ok()?, count.parse().ok()?))
    } else {
        Some((spec.parse().ok()?, 1))
    }
}

/// Parse hunk content and return new content
fn parse_hunk_content(lines: &[&str]) -> (u32, String) {
    let mut new_content = Vec::new();
    let old_start = 0u32;

    for line in lines {
        if line.starts_with("@@") {
            break;
        }

        if line.starts_with('+') && !line.starts_with("+++") {
            new_content.push(&line[1..]);
        } else if line.starts_with('-') && !line.starts_with("---") {
            // Skip removed lines
        } else if line.starts_with(' ') {
            // Context line - include in new content
            new_content.push(&line[1..]);
        }
    }

    (old_start, new_content.join("\n"))
}

#[tower_lsp::async_trait]
impl LanguageServer for UnfaultLsp {
    async fn initialize(&self, params: InitializeParams) -> RpcResult<InitializeResult> {
        self.log_debug("LSP initialize called");

        // Store workspace root
        if let Some(root_uri) = params.root_uri {
            if let Ok(path) = root_uri.to_file_path() {
                self.log_debug(&format!("Workspace root: {:?}", path));

                // Compute workspace ID
                let git_remote = get_git_remote(&path);
                let workspace_label = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string());

                let workspace_id_result =
                    compute_workspace_id(git_remote.as_deref(), None, workspace_label.as_deref());

                let workspace_id = workspace_id_result
                    .map(|r| r.id)
                    .unwrap_or_else(|| format!("wks_{}", uuid::Uuid::new_v4().simple()));

                self.log_debug(&format!("Workspace ID: {}", workspace_id));

                {
                    let mut root = self.workspace_root.write().await;
                    *root = Some(path);
                }
                {
                    let mut id = self.workspace_id.write().await;
                    *id = Some(workspace_id);
                }
            }
        }

        // Apply initialization options (VS Code extension settings)
        if let Some(options) = params.initialization_options {
            let mut settings = self.settings.write().await;
            apply_lsp_settings(&mut settings, &options);
            self.log_debug(&format!(
                "Settings: diagnostics.enabled={} minSeverity={:?}",
                settings.diagnostics.enabled, settings.diagnostics.min_severity
            ));
        }

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                // We use the "push" model via publishDiagnostics, not the "pull" model
                // Do NOT set diagnostic_provider as that enables textDocument/diagnostic requests
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![
                        "unfault/getFunctionImpact".to_string(),
                        "unfault/getFileCentrality".to_string(),
                        "unfault/getFileDependencies".to_string(),
                        "unfault/refreshFile".to_string(),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "unfault-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.log_debug("LSP initialized");

        // Log whether we have authentication
        if self.config.is_some() {
            self.client
                .log_message(MessageType::INFO, "Unfault LSP ready")
                .await;
        } else {
            self.client
                .log_message(
                    MessageType::WARNING,
                    "Unfault: No API key configured. Run 'unfault login' to authenticate.",
                )
                .await;
        }
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        // Accept either: { unfault: { diagnostics: ... } } or { diagnostics: ... }
        {
            let mut settings = self.settings.write().await;
            apply_lsp_settings(&mut settings, &params.settings);
            self.log_debug(&format!(
                "Settings updated: diagnostics.enabled={} minSeverity={:?}",
                settings.diagnostics.enabled, settings.diagnostics.min_severity
            ));
        }

        // Apply changes immediately without requiring restart.
        self.republish_diagnostics_for_open_documents().await;
    }

    async fn shutdown(&self) -> RpcResult<()> {
        self.log_debug("LSP shutdown");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.log_debug(&format!("Document opened: {}", params.text_document.uri));

        // Cache the document content for code actions
        let _ = self
            .document_cache
            .insert_async(
                params.text_document.uri.clone(),
                params.text_document.text.clone(),
            )
            .await;

        // Get IDE workspace root
        let workspace_root = {
            let root = self.workspace_root.read().await;
            root.clone()
        };

        // Get absolute file path from URI
        let abs_path = params.text_document.uri.to_file_path().ok();

        // Determine the project root for this file (may differ from IDE workspace in monorepos)
        // and compute the relative path using the SAME root that build_ir_cached will use.
        // This is critical: paths in the graph are stored relative to project_root, not IDE workspace.
        let (project_root, relative_path) = if let Some(ref abs) = abs_path {
            let ide_ws = workspace_root.as_ref();
            let proj_root = find_project_root(abs, ide_ws).unwrap_or_else(|| {
                ide_ws
                    .cloned()
                    .unwrap_or_else(|| abs.parent().unwrap_or(abs).to_path_buf())
            });

            // Compute relative path from project_root (same as build_ir_cached does)
            let rel = abs
                .strip_prefix(&proj_root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| {
                    abs.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string()
                });

            (Some(proj_root), rel)
        } else {
            (None, String::new())
        };

        // Build IR locally first - this gives us the graph for dependency analysis
        // even before the API call completes (or if it fails)
        let local_ir = if let Some(ref proj_root) = project_root {
            match build_ir_cached(proj_root, None, self.verbose, None) {
                Ok(result) => Some(result.ir),
                Err(e) => {
                    self.log_debug(&format!("Failed to build IR for local graph: {}", e));
                    None
                }
            }
        } else {
            None
        };

        // Send local dependencies notification IMMEDIATELY if we have the graph
        // This provides instant feedback even on first open, before any API session exists
        if let Some(ref ir) = local_ir {
            if !relative_path.is_empty() {
                self.log_debug(&format!(
                    "Looking for file in graph: '{}' (graph has {} files)",
                    relative_path,
                    ir.graph.stats().file_count
                ));
                if let Some(dependencies) = self.compute_local_dependencies(ir, &relative_path) {
                    self.log_debug(&format!(
                        "Sending local dependencies notification: {} direct, {} total for {}",
                        dependencies.direct_dependents.len(),
                        dependencies.total_count,
                        relative_path
                    ));
                    let _ = self
                        .client
                        .send_notification::<FileDependenciesNotificationType>(dependencies)
                        .await;
                } else {
                    self.log_debug(&format!(
                        "No file found in graph for path: '{}'",
                        relative_path
                    ));
                }

                // Extract functions from IR semantics and populate function_cache
                // This enables function hover/impact analysis
                let functions = self.extract_functions_from_ir(ir, &relative_path);
                if !functions.is_empty() {
                    self.log_debug(&format!(
                        "Caching {} functions for hover from {}",
                        functions.len(),
                        relative_path
                    ));
                    self.function_cache
                        .insert(params.text_document.uri.clone(), functions);
                }
            }
        }

        // Now run the full analysis (includes API call)
        // Pass the pre-built IR to avoid rebuilding it
        self.analyze_document(
            &params.text_document.uri,
            &params.text_document.text,
            params.text_document.version,
            local_ir,
        )
        .await;

        // Send file centrality notification (from API cache or fetch)
        if !relative_path.is_empty() {
            if let Some(centrality) = self.get_file_centrality(&relative_path).await {
                let _ = self
                    .client
                    .send_notification::<FileCentralityNotificationType>(centrality)
                    .await;
            }
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        self.log_debug(&format!("Document changed: {}", params.text_document.uri));

        // Get the full text from the last change event (since we use FULL sync)
        // This fires on every edit including Ctrl-Z (undo), keeping the cache current
        if let Some(change) = params.content_changes.last() {
            // Update the document cache with the new content
            let _ = self
                .document_cache
                .insert_async(params.text_document.uri.clone(), change.text.clone())
                .await;

            // NOTE: We intentionally do NOT run full analysis on every change.
            // Full analysis (IR build + API call) is expensive and would lag the editor.
            // Analysis runs on:
            // - did_open (file opened)
            // - did_save (file saved)
            // The document cache is kept up-to-date for code actions to work.
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        self.log_debug(&format!("Document saved: {}", params.text_document.uri));

        // Re-analyze on save with saved text if available
        if let Some(text) = params.text {
            self.analyze_document(&params.text_document.uri, &text, 0, None)
                .await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.log_debug(&format!("Document closed: {}", params.text_document.uri));

        // Clear cached findings
        self.findings_cache.remove(&params.text_document.uri);

        // Clear cached document content
        let _ = self
            .document_cache
            .remove_async(&params.text_document.uri)
            .await;

        // Clear cached function info
        self.function_cache.remove(&params.text_document.uri);

        // Clear diagnostics
        self.client
            .publish_diagnostics(params.text_document.uri, vec![], None)
            .await;
    }

    async fn code_action(&self, params: CodeActionParams) -> RpcResult<Option<CodeActionResponse>> {
        self.log_debug(&format!(
            "Code action requested for: {}",
            params.text_document.uri
        ));

        // Retrieve document content from cache for accurate edit position calculations
        let source_text = self
            .document_cache
            .get_async(&params.text_document.uri)
            .await
            .map(|entry| entry.get().clone())
            .unwrap_or_default();

        let actions =
            self.get_code_actions_for_range(&params.text_document.uri, &params.range, &source_text);

        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                actions
                    .into_iter()
                    .map(CodeActionOrCommand::CodeAction)
                    .collect(),
            ))
        }
    }

    async fn hover(&self, params: HoverParams) -> RpcResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        self.log_debug(&format!(
            "Hover requested at {}:{}:{}",
            uri, position.line, position.character
        ));

        // Get file path from URI
        let file_path = match uri.to_file_path() {
            Ok(path) => path,
            Err(_) => {
                self.log_debug("Could not convert URI to file path for hover");
                return Ok(None);
            }
        };

        // Find the project root for this file (same logic as did_open)
        // Graph paths are stored relative to the workspace root, not project root
        let workspace_root = {
            let root = self.workspace_root.read().await;
            root.clone()
        };

        self.log_debug(&format!("Workspace root: {:?}", workspace_root));
        self.log_debug(&format!("File path: {:?}", file_path));

        // Use workspace root for computing relative path
        let relative_path = if let Some(ws_root) = workspace_root.as_ref() {
            if let Ok(rel) = file_path.strip_prefix(ws_root) {
                rel.to_string_lossy().to_string()
            } else {
                self.log_debug("Failed to strip workspace root, using full path");
                file_path.to_string_lossy().to_string()
            }
        } else {
            self.log_debug("No workspace root available, using full path");
            file_path.to_string_lossy().to_string()
        };

        // Try to get function at position from cache
        if let Some(function_name) = self.get_function_at_position(uri, position).await {
            self.log_debug(&format!("Found function at position: {}", function_name));
            self.log_debug(&format!("Using relative path: {}", relative_path));

            // Look up function's line range from cache for function-scoped findings
            let (start_line, end_line) = self
                .function_cache
                .get(uri)
                .and_then(|functions| {
                    functions
                        .iter()
                        .find(|f| f.name == function_name)
                        .map(|f| {
                            // LSP lines are 0-based, API expects 1-based
                            (
                                Some((f.range.start.line + 1) as i32),
                                Some((f.range.end.line + 1) as i32),
                            )
                        })
                })
                .unwrap_or((None, None));

            // Get function impact analysis
            if let Some(markdown) = self
                .get_function_impact(&relative_path, &function_name, start_line, end_line)
                .await
            {
                return Ok(Some(Hover {
                    contents: HoverContents::Markup(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: markdown,
                    }),
                    range: None,
                }));
            }
        }

        // Check if there's a finding at this position and show context
        if let Some(findings) = self.findings_cache.get(uri) {
            for cached in findings.iter() {
                let finding = &cached.finding;

                // Check if position is within finding range
                let finding_start_line = finding.line.saturating_sub(1);
                let finding_end_line = finding.end_line.unwrap_or(finding.line).saturating_sub(1);

                if position.line >= finding_start_line && position.line <= finding_end_line {
                    // Build contextual hover content
                    let mut markdown = String::new();
                    markdown.push_str(&format!("**{}**\n\n", finding.title));
                    markdown.push_str(&format!("{}\n\n", finding.description));

                    if !finding.dimension.is_empty() {
                        markdown.push_str(&format!("*Dimension:* {}\n", finding.dimension));
                    }

                    if finding.patch.is_some() || finding.patch_json.is_some() {
                        markdown.push_str("\n💡 *Quick fix available*\n");
                    }

                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: markdown,
                        }),
                        range: Some(Range {
                            start: Position {
                                line: finding_start_line,
                                character: finding.column.saturating_sub(1),
                            },
                            end: Position {
                                line: finding_end_line,
                                character: finding
                                    .end_column
                                    .unwrap_or(finding.column + 10)
                                    .saturating_sub(1),
                            },
                        }),
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn execute_command(
        &self,
        params: ExecuteCommandParams,
    ) -> RpcResult<Option<serde_json::Value>> {
        let args_value = params
            .arguments
            .first()
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match params.command.as_str() {
            "unfault/getFunctionImpact" => {
                self.handle_get_function_impact(args_value).await
            }
            "unfault/getFileCentrality" => {
                self.handle_get_file_centrality(args_value).await
            }
            "unfault/getFileDependencies" => {
                self.handle_get_file_dependencies(args_value).await
            }
            "unfault/refreshFile" => {
                self.handle_refresh_file(args_value).await
            }
            _ => Err(tower_lsp::jsonrpc::Error::method_not_found()),
        }
    }
}

// Command handlers for execute_command
impl UnfaultLsp {
    async fn handle_get_function_impact(
        &self,
        args: serde_json::Value,
    ) -> RpcResult<Option<serde_json::Value>> {
        let req: GetFunctionImpactRequest = serde_json::from_value(args)
            .map_err(|e| tower_lsp::jsonrpc::Error::invalid_params(e.to_string()))?;

        let uri = Url::parse(&req.uri).ok();
        let file_path = uri.as_ref().and_then(|u| u.to_file_path().ok());
        let workspace_root = { self.workspace_root.read().await.clone() };
        let relative_path = match (&file_path, &workspace_root) {
            (Some(fp), Some(ws)) => fp
                .strip_prefix(ws)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| fp.to_string_lossy().to_string()),
            (Some(fp), None) => fp.to_string_lossy().to_string(),
            _ => return Ok(None),
        };
        let api_key = match &self.config {
            Some(c) => c.api_key.clone(),
            None => return Ok(None),
        };
        let workspace_id = match self.workspace_id.read().await.clone() {
            Some(id) => id,
            None => return Ok(None),
        };

        let git_remote = workspace_root.as_ref().and_then(|p| get_git_remote(p));
        let file_id = Some(compute_file_id(
            git_remote.as_deref(),
            &workspace_id,
            &relative_path,
        ));

        // Look up function's line range from cache for function-scoped findings
        let (start_line, end_line) = uri
            .as_ref()
            .and_then(|u| self.function_cache.get(u))
            .and_then(|functions| {
                functions
                    .iter()
                    .find(|f| f.name == req.function_name)
                    .map(|f| {
                        // LSP lines are 0-based, API expects 1-based
                        (
                            Some((f.range.start.line + 1) as i32),
                            Some((f.range.end.line + 1) as i32),
                        )
                    })
            })
            .unwrap_or((None, None));

        let impact_request = crate::api::graph::FunctionImpactRequest {
            session_id: None,
            workspace_id: Some(workspace_id),
            file_id,
            file_path: relative_path,
            function_name: req.function_name.clone(),
            start_line,
            end_line,
            max_depth: 5,
        };
        let response = match self
            .api_client
            .graph_function_impact(&api_key, &impact_request)
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        // Include ALL callers (including route handlers) in the callers list
        let mut callers = Vec::new();
        for c in response
            .direct_callers
            .iter()
            .chain(response.transitive_callers.iter())
        {
            callers.push(FunctionImpactCaller {
                name: c.function.clone(),
                calls: c.calls.clone(),
                file: c.path.clone(),
                depth: c.depth,
            });
        }
        let mut routes = Vec::new();

        // If the target function itself is a route handler, include it first
        if response.is_route_handler {
            if let (Some(m), Some(p)) = (&response.route_method, &response.route_path) {
                let slos = response.slos.as_ref().map(|slo_list| {
                    slo_list
                        .iter()
                        .map(|s| FunctionImpactSlo {
                            name: s.name.clone(),
                            provider: s.provider.clone(),
                            target_percent: s.target_percent,
                            error_budget_remaining: s.error_budget_remaining,
                            dashboard_url: s.dashboard_url.clone(),
                        })
                        .collect()
                });
                routes.push(FunctionImpactRoute {
                    method: m.to_uppercase(),
                    path: p.clone(),
                    slos,
                });
            }
        }

        // Also include routes from callers (for nested functions)
        for c in response
            .direct_callers
            .iter()
            .chain(response.transitive_callers.iter())
            .filter(|c| c.is_route_handler)
        {
            if let (Some(m), Some(p)) = (&c.route_method, &c.route_path) {
                let slos = c.slos.as_ref().map(|slo_list| {
                    slo_list
                        .iter()
                        .map(|s| FunctionImpactSlo {
                            name: s.name.clone(),
                            provider: s.provider.clone(),
                            target_percent: s.target_percent,
                            error_budget_remaining: s.error_budget_remaining,
                            dashboard_url: s.dashboard_url.clone(),
                        })
                        .collect()
                });
                routes.push(FunctionImpactRoute {
                    method: m.to_uppercase(),
                    path: p.clone(),
                    slos,
                });
            }
        }

        // Use findings directly from API response
        // The API uses incremental sessions which delete old findings before inserting new ones,
        // so the database always reflects the current state of the code
        let findings: Vec<FunctionImpactFinding> = response
            .findings
            .iter()
            .map(|f| FunctionImpactFinding {
                severity: normalize_severity(&f.severity),
                message: format!(
                    "{}: {}",
                    f.title,
                    f.description.lines().next().unwrap_or("")
                ),
                learn_more: Some(format!(
                    "https://docs.unfault.dev/rules/{}",
                    f.rule_id.replace('.', "/")
                )),
            })
            .collect();

        // Path findings are findings from callers in the call path
        let path_findings: Vec<FunctionImpactFinding> = response
            .path_findings
            .into_iter()
            .map(|f| FunctionImpactFinding {
                severity: normalize_severity(&f.severity),
                message: format!(
                    "{}: {}",
                    f.title,
                    f.description.lines().next().unwrap_or("")
                ),
                learn_more: Some(format!(
                    "https://docs.unfault.dev/rules/{}",
                    f.rule_id.replace('.', "/")
                )),
            })
            .collect();

        let insights = summarize_findings(&findings);
        let path_insights = summarize_findings(&path_findings);
        
        Ok(Some(
            serde_json::to_value(GetFunctionImpactResponse {
                name: response.function,
                callers,
                routes,
                findings,
                insights,
                path_insights,
            })
            .unwrap(),
        ))
    }

    async fn handle_get_file_centrality(
        &self,
        args: serde_json::Value,
    ) -> RpcResult<Option<serde_json::Value>> {
        let req: GetFileCentralityRequest = serde_json::from_value(args)
            .map_err(|e| tower_lsp::jsonrpc::Error::invalid_params(e.to_string()))?;

        let uri = Url::parse(&req.uri).ok();
        let file_path = uri.as_ref().and_then(|u| u.to_file_path().ok());
        let workspace_root = { self.workspace_root.read().await.clone() };
        let relative_path = match (&file_path, &workspace_root) {
            (Some(fp), Some(ws)) => fp
                .strip_prefix(ws)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| fp.to_string_lossy().to_string()),
            (Some(fp), None) => fp.to_string_lossy().to_string(),
            _ => return Ok(None),
        };

        if relative_path.is_empty() {
            return Ok(None);
        }

        match self.get_file_centrality(&relative_path).await {
            Some(centrality) => Ok(Some(serde_json::to_value(centrality).unwrap())),
            None => Ok(None),
        }
    }

    async fn handle_get_file_dependencies(
        &self,
        args: serde_json::Value,
    ) -> RpcResult<Option<serde_json::Value>> {
        let req: GetFileDependenciesRequest = serde_json::from_value(args)
            .map_err(|e| tower_lsp::jsonrpc::Error::invalid_params(e.to_string()))?;

        let uri = Url::parse(&req.uri)
            .map_err(|e| tower_lsp::jsonrpc::Error::invalid_params(e.to_string()))?;
        let file_path = uri
            .to_file_path()
            .map_err(|_| tower_lsp::jsonrpc::Error::invalid_params("Invalid file URI"))?;

        // Get workspace root
        let workspace_root = { self.workspace_root.read().await.clone() };
        let ide_workspace_root = workspace_root.as_ref();

        // Find project root (same logic as did_open/did_save)
        let project_root = find_project_root(&file_path, ide_workspace_root).unwrap_or_else(|| {
            ide_workspace_root
                .cloned()
                .unwrap_or_else(|| file_path.parent().unwrap_or(&file_path).to_path_buf())
        });

        let relative_path = file_path
            .strip_prefix(&project_root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if relative_path.is_empty() {
            return Ok(None);
        }

        // Get document content from cache for accurate IR
        let content_overrides = if let Some(content) = self.document_cache.get_async(&uri).await {
            let mut map = std::collections::HashMap::new();
            map.insert(file_path.clone(), content.get().clone());
            Some(map)
        } else {
            None
        };

        // Build IR to compute dependencies
        let ir = match build_ir_cached(
            &project_root,
            None,
            self.verbose,
            content_overrides.as_ref(),
        ) {
            Ok(result) => result.ir,
            Err(e) => {
                self.log_debug(&format!("Failed to build IR for dependencies: {}", e));
                return Ok(None);
            }
        };

        match self.compute_local_dependencies(&ir, &relative_path) {
            Some(deps) => Ok(Some(serde_json::to_value(deps).unwrap())),
            None => Ok(None),
        }
    }

    /// Handle unfault/refreshFile - re-analyze a single file and return updated findings.
    /// This is optimized to only parse and analyze the single file, not the entire workspace.
    /// Requires a prior full analysis to have cached the session_id.
    async fn handle_refresh_file(
        &self,
        args: serde_json::Value,
    ) -> RpcResult<Option<serde_json::Value>> {
        let req: RefreshFileRequest = serde_json::from_value(args)
            .map_err(|e| tower_lsp::jsonrpc::Error::invalid_params(e.to_string()))?;

        let uri = Url::parse(&req.uri)
            .map_err(|e| tower_lsp::jsonrpc::Error::invalid_params(e.to_string()))?;

        self.log_debug(&format!("Refreshing single file: {}", uri));

        // Get cached session_id from prior full analysis
        let session_id = match self.session_id.read().await.clone() {
            Some(id) => id,
            None => {
                self.log_debug("No session_id cached - need full analysis first");
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        // Get document content from cache (includes unsaved changes)
        let text = match self.document_cache.get_async(&uri).await {
            Some(content) => content.get().clone(),
            None => {
                self.log_debug("Document not in cache, cannot refresh");
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        // Get file path from URI
        let file_path = match uri.to_file_path() {
            Ok(path) => path,
            Err(_) => {
                self.log_debug("Could not convert URI to file path");
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        // Get workspace root and compute relative path
        let workspace_root = { self.workspace_root.read().await.clone() };
        let ide_workspace_root = workspace_root.as_ref();
        let project_root = find_project_root(&file_path, ide_workspace_root).unwrap_or_else(|| {
            ide_workspace_root
                .cloned()
                .unwrap_or_else(|| file_path.parent().unwrap_or(&file_path).to_path_buf())
        });

        let relative_path = file_path
            .strip_prefix(&project_root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if relative_path.is_empty() {
            self.log_debug("Could not compute relative path");
            return Ok(Some(serde_json::to_value(RefreshFileResponse {
                success: false,
                finding_count: 0,
            }).unwrap()));
        }

        // Get API key
        let api_key = match &self.config {
            Some(config) => config.api_key.clone(),
            None => {
                self.log_debug("No API key configured");
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        // Detect language from file extension
        let language = match file_path.extension().and_then(|e| e.to_str()) {
            Some("py") => unfault_core::types::context::Language::Python,
            Some("go") => unfault_core::types::context::Language::Go,
            Some("rs") => unfault_core::types::context::Language::Rust,
            Some("ts" | "tsx" | "js" | "jsx") => unfault_core::types::context::Language::Typescript,
            _ => {
                self.log_debug("Unsupported language");
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        // Parse the single file using the same approach as ir_builder
        let file_id = unfault_core::parse::ast::FileId(1);
        let source_file = unfault_core::types::context::SourceFile {
            path: relative_path.clone(),
            language,
            content: text.clone(),
        };

        let semantics = match language {
            unfault_core::types::context::Language::Python => {
                use unfault_core::parse::python::parse_python_file;
                use unfault_core::semantics::python::model::PyFileSemantics;
                
                let parsed = match parse_python_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(e) => {
                        self.log_debug(&format!("Parse error: {}", e));
                        return Ok(Some(serde_json::to_value(RefreshFileResponse {
                            success: false,
                            finding_count: 0,
                        }).unwrap()));
                    }
                };
                let mut sem = PyFileSemantics::from_parsed(&parsed);
                let _ = sem.analyze_frameworks(&parsed);
                vec![unfault_core::SourceSemantics::Python(sem)]
            }
            unfault_core::types::context::Language::Go => {
                use unfault_core::parse::go::parse_go_file;
                use unfault_core::semantics::go::model::GoFileSemantics;
                
                let parsed = match parse_go_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(e) => {
                        self.log_debug(&format!("Parse error: {}", e));
                        return Ok(Some(serde_json::to_value(RefreshFileResponse {
                            success: false,
                            finding_count: 0,
                        }).unwrap()));
                    }
                };
                let mut sem = GoFileSemantics::from_parsed(&parsed);
                let _ = sem.analyze_frameworks(&parsed);
                vec![unfault_core::SourceSemantics::Go(sem)]
            }
            unfault_core::types::context::Language::Rust => {
                use unfault_core::parse::rust::parse_rust_file;
                use unfault_core::semantics::rust::model::RustFileSemantics;
                
                let parsed = match parse_rust_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(e) => {
                        self.log_debug(&format!("Parse error: {}", e));
                        return Ok(Some(serde_json::to_value(RefreshFileResponse {
                            success: false,
                            finding_count: 0,
                        }).unwrap()));
                    }
                };
                let sem = RustFileSemantics::from_parsed(&parsed);
                vec![unfault_core::SourceSemantics::Rust(sem)]
            }
            unfault_core::types::context::Language::Typescript
            | unfault_core::types::context::Language::Javascript => {
                use unfault_core::parse::typescript::parse_typescript_file;
                use unfault_core::semantics::typescript::model::TsFileSemantics;
                
                let parsed = match parse_typescript_file(file_id, &source_file) {
                    Ok(p) => p,
                    Err(e) => {
                        self.log_debug(&format!("Parse error: {}", e));
                        return Ok(Some(serde_json::to_value(RefreshFileResponse {
                            success: false,
                            finding_count: 0,
                        }).unwrap()));
                    }
                };
                let mut sem = TsFileSemantics::from_parsed(&parsed);
                let _ = sem.analyze_frameworks(&parsed);
                vec![unfault_core::SourceSemantics::Typescript(sem)]
            }
            unfault_core::types::context::Language::Java => {
                // Java not yet supported for single-file refresh
                self.log_debug("Java not supported for single-file refresh");
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        // Serialize semantics
        let semantics_json = match serde_json::to_string(&semantics) {
            Ok(json) => json,
            Err(e) => {
                self.log_debug(&format!("Serialization error: {}", e));
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        // Detect profiles
        let mut scanner = WorkspaceScanner::new(&project_root);
        let workspace_info = match scanner.scan() {
            Ok(info) => info,
            Err(_) => {
                self.log_debug("Failed to scan workspace for profiles");
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };
        let profiles: Vec<String> = workspace_info
            .to_workspace_descriptor()
            .profiles
            .iter()
            .map(|p| p.id.clone())
            .collect();

        self.log_debug(&format!(
            "Analyzing single file {} with cached session {}",
            relative_path, session_id
        ));

        // Call API with incremental=true to update only this file's findings
        let response = match self
            .api_client
            .analyze_ir(
                &api_key,
                &session_id,
                &profiles,
                semantics_json,
                true, // incremental: delete old findings for this file before inserting new
            )
            .await
        {
            Ok(response) => response,
            Err(e) => {
                self.log_debug(&format!("API error: {:?}", e));
                return Ok(Some(serde_json::to_value(RefreshFileResponse {
                    success: false,
                    finding_count: 0,
                }).unwrap()));
            }
        };

        self.log_debug(&format!(
            "Single file analysis returned {} findings",
            response.findings.len()
        ));

        // Filter findings for this file and update cache + diagnostics
        let settings = { self.settings.read().await.clone() };
        let mut diagnostics = Vec::new();
        let mut cached_findings = Vec::new();

        for finding in &response.findings {
            if !finding.file_path.ends_with(&relative_path)
                && !relative_path.ends_with(&finding.file_path)
            {
                continue;
            }

            cached_findings.push(CachedFinding {
                finding: finding.clone(),
                version: 0,
            });

            if settings.diagnostics.enabled {
                let finding_severity =
                    FindingSeverityThreshold::from_finding_severity(&finding.severity);
                if finding_severity.rank() >= settings.diagnostics.min_severity.rank() {
                    diagnostics.push(self.finding_to_diagnostic(finding, &text));
                }
            }
        }

        let finding_count = cached_findings.len() as i32;

        // Update findings cache
        self.findings_cache.insert(uri.clone(), cached_findings);

        // Publish diagnostics
        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;

        // Send analysis complete notification
        let _ = self
            .client
            .send_notification::<AnalysisCompleteNotificationType>(AnalysisCompleteNotification {
                uri: uri.to_string(),
                finding_count,
            })
            .await;

        Ok(Some(serde_json::to_value(RefreshFileResponse {
            success: true,
            finding_count,
        }).unwrap()))
    }
}

/// Custom notification type for file centrality
struct FileCentralityNotificationType;

impl tower_lsp::lsp_types::notification::Notification for FileCentralityNotificationType {
    type Params = FileCentralityNotification;
    const METHOD: &'static str = "unfault/fileCentrality";
}

/// Custom notification type for file dependencies
struct FileDependenciesNotificationType;

impl tower_lsp::lsp_types::notification::Notification for FileDependenciesNotificationType {
    type Params = FileDependenciesNotification;
    const METHOD: &'static str = "unfault/fileDependencies";
}

/// Notification sent when analysis completes for a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCompleteNotification {
    /// URI of the analyzed file
    pub uri: String,
    /// Number of findings for this file
    pub finding_count: i32,
}

/// Custom notification type for analysis complete
struct AnalysisCompleteNotificationType;

impl tower_lsp::lsp_types::notification::Notification for AnalysisCompleteNotificationType {
    type Params = AnalysisCompleteNotification;
    const METHOD: &'static str = "unfault/analysisComplete";
}

/// Execute the LSP command
///
/// This starts the LSP server and runs until the client disconnects.
///
/// # Arguments
///
/// * `args` - LSP command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Server ran and shut down cleanly
/// * `Ok(EXIT_CONFIG_ERROR)` - Configuration error
pub async fn execute(args: LspArgs) -> anyhow::Result<i32> {
    if args.verbose {
        eprintln!("[unfault-lsp] Starting LSP server");
    }

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::build(|client| UnfaultLsp::new(client, args.verbose))
        .custom_method(
            "unfault/getFunctionImpact",
            UnfaultLsp::handle_get_function_impact,
        )
        .finish();

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(EXIT_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_lsp_settings_default_is_quiet() {
        let settings = LspClientSettings::default();
        assert!(!settings.diagnostics.enabled);
        assert_eq!(
            settings.diagnostics.min_severity,
            FindingSeverityThreshold::High
        );
    }

    #[test]
    fn test_apply_lsp_settings_updates_diagnostics() {
        let mut settings = LspClientSettings::default();

        apply_lsp_settings(
            &mut settings,
            &serde_json::json!({
                "unfault": {
                    "diagnostics": { "enabled": true, "minSeverity": "critical" }
                }
            }),
        );

        assert!(settings.diagnostics.enabled);
        assert_eq!(
            settings.diagnostics.min_severity,
            FindingSeverityThreshold::Critical
        );

        // Unknown values should not crash and should keep existing.
        apply_lsp_settings(
            &mut settings,
            &serde_json::json!({
                "unfault": {
                    "diagnostics": { "minSeverity": "unknown" }
                }
            }),
        );

        assert_eq!(
            settings.diagnostics.min_severity,
            FindingSeverityThreshold::Critical
        );
    }

    #[test]
    fn test_severity_threshold_rank_ordering() {
        assert!(FindingSeverityThreshold::Critical.rank() > FindingSeverityThreshold::High.rank());
        assert!(FindingSeverityThreshold::High.rank() > FindingSeverityThreshold::Medium.rank());
        assert!(FindingSeverityThreshold::Medium.rank() > FindingSeverityThreshold::Low.rank());
    }

    #[test]
    fn test_find_project_root_with_pyproject() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path().join("myproject");
        fs::create_dir_all(&project_dir).unwrap();

        // Create pyproject.toml in project directory
        fs::write(
            project_dir.join("pyproject.toml"),
            "[project]\nname = \"test\"",
        )
        .unwrap();

        // Create a nested source file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let file_path = src_dir.join("main.py");
        fs::write(&file_path, "print('hello')").unwrap();

        // Find project root from the source file
        let result = find_project_root(&file_path, None);
        assert_eq!(result, Some(project_dir));
    }

    #[test]
    fn test_find_project_root_with_package_json() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path().join("myproject");
        fs::create_dir_all(&project_dir).unwrap();

        // Create package.json in project directory
        fs::write(project_dir.join("package.json"), r#"{"name": "test"}"#).unwrap();

        // Create a nested source file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let file_path = src_dir.join("index.ts");
        fs::write(&file_path, "console.log('hello')").unwrap();

        // Find project root from the source file
        let result = find_project_root(&file_path, None);
        assert_eq!(result, Some(project_dir));
    }

    #[test]
    fn test_find_project_root_monorepo() {
        let temp_dir = TempDir::new().unwrap();

        // Create monorepo structure
        let monorepo_root = temp_dir.path();
        fs::write(
            monorepo_root.join("package.json"),
            r#"{"name": "monorepo"}"#,
        )
        .unwrap();

        // Create a sub-project
        let subproject_dir = monorepo_root.join("packages").join("myapp");
        fs::create_dir_all(&subproject_dir).unwrap();
        fs::write(
            subproject_dir.join("pyproject.toml"),
            "[project]\nname = \"myapp\"",
        )
        .unwrap();

        // Create a source file in the sub-project
        let src_dir = subproject_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let file_path = src_dir.join("main.py");
        fs::write(&file_path, "print('hello')").unwrap();

        // Find project root should return the sub-project, not the monorepo root
        let result = find_project_root(&file_path, Some(&monorepo_root.to_path_buf()));
        assert_eq!(result, Some(subproject_dir));
    }

    #[test]
    fn test_find_project_root_no_marker() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("random.py");
        fs::write(&file_path, "print('hello')").unwrap();

        // No project marker exists
        let result = find_project_root(&file_path, None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_project_root_with_git() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path().join("myproject");
        fs::create_dir_all(&project_dir).unwrap();

        // Create .git directory (fallback marker)
        fs::create_dir_all(project_dir.join(".git")).unwrap();

        // Create a source file
        let file_path = project_dir.join("main.py");
        fs::write(&file_path, "print('hello')").unwrap();

        // Find project root from the source file
        let result = find_project_root(&file_path, None);
        assert_eq!(result, Some(project_dir));
    }

    // ==================== byte_offset_to_position tests ====================

    #[test]
    fn test_byte_offset_to_position_start_of_first_line() {
        let source = "line1\nline2\nline3";
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(
                source
                    .char_indices()
                    .filter_map(|(idx, ch)| if ch == '\n' { Some(idx + 1) } else { None }),
            )
            .chain(std::iter::once(source.len()))
            .collect();
        let source_lines: Vec<&str> = source.lines().collect();

        // Offset 0 should be line 0, col 0
        let result = byte_offset_to_position(&line_starts, &source_lines, 0);
        assert_eq!(result, Some((0, 0)));
    }

    #[test]
    fn test_byte_offset_to_position_middle_of_first_line() {
        let source = "line1\nline2\nline3";
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(
                source
                    .char_indices()
                    .filter_map(|(idx, ch)| if ch == '\n' { Some(idx + 1) } else { None }),
            )
            .chain(std::iter::once(source.len()))
            .collect();
        let source_lines: Vec<&str> = source.lines().collect();

        // Offset 3 should be line 0, col 3
        let result = byte_offset_to_position(&line_starts, &source_lines, 3);
        assert_eq!(result, Some((0, 3)));
    }

    #[test]
    fn test_byte_offset_to_position_start_of_second_line() {
        let source = "line1\nline2\nline3";
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(
                source
                    .char_indices()
                    .filter_map(|(idx, ch)| if ch == '\n' { Some(idx + 1) } else { None }),
            )
            .chain(std::iter::once(source.len()))
            .collect();
        let source_lines: Vec<&str> = source.lines().collect();

        // Offset 6 (after first \n) should be line 1, col 0
        let result = byte_offset_to_position(&line_starts, &source_lines, 6);
        assert_eq!(result, Some((1, 0)));
    }

    #[test]
    fn test_byte_offset_to_position_middle_of_second_line() {
        let source = "line1\nline2\nline3";
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(
                source
                    .char_indices()
                    .filter_map(|(idx, ch)| if ch == '\n' { Some(idx + 1) } else { None }),
            )
            .chain(std::iter::once(source.len()))
            .collect();
        let source_lines: Vec<&str> = source.lines().collect();

        // Offset 8 should be line 1, col 2
        let result = byte_offset_to_position(&line_starts, &source_lines, 8);
        assert_eq!(result, Some((1, 2)));
    }

    #[test]
    fn test_byte_offset_to_position_end_of_file() {
        let source = "line1\nline2\nline3";
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(
                source
                    .char_indices()
                    .filter_map(|(idx, ch)| if ch == '\n' { Some(idx + 1) } else { None }),
            )
            .chain(std::iter::once(source.len()))
            .collect();
        let source_lines: Vec<&str> = source.lines().collect();

        // Offset at EOF should be last line, last column
        let result = byte_offset_to_position(&line_starts, &source_lines, source.len());
        assert_eq!(result, Some((2, 5))); // line3 has 5 chars
    }

    // ==================== FilePatch JSON parsing tests ====================

    #[test]
    fn test_parse_file_patch_json_insert_after_line() {
        use unfault_core::parse::ast::FileId;
        use unfault_core::types::{FilePatch, PatchHunk, PatchRange};

        let patch = FilePatch {
            file_id: FileId(1),
            hunks: vec![
                PatchHunk {
                    range: PatchRange::InsertAfterLine { line: 1 },
                    replacement: "from fastapi.middleware.cors import CORSMiddleware\n".to_string(),
                },
                PatchHunk {
                    range: PatchRange::InsertAfterLine { line: 5 },
                    replacement: "\napp.add_middleware(CORSMiddleware)\n".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&patch).unwrap();
        let parsed: FilePatch = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.hunks.len(), 2);
        match &parsed.hunks[0].range {
            PatchRange::InsertAfterLine { line } => assert_eq!(*line, 1),
            _ => panic!("Expected InsertAfterLine"),
        }
        match &parsed.hunks[1].range {
            PatchRange::InsertAfterLine { line } => assert_eq!(*line, 5),
            _ => panic!("Expected InsertAfterLine"),
        }
    }

    #[test]
    fn test_parse_file_patch_json_insert_before_line() {
        use unfault_core::parse::ast::FileId;
        use unfault_core::types::{FilePatch, PatchHunk, PatchRange};

        let patch = FilePatch {
            file_id: FileId(1),
            hunks: vec![PatchHunk {
                range: PatchRange::InsertBeforeLine { line: 3 },
                replacement: "# Comment\n".to_string(),
            }],
        };

        let json = serde_json::to_string(&patch).unwrap();
        let parsed: FilePatch = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.hunks.len(), 1);
        match &parsed.hunks[0].range {
            PatchRange::InsertBeforeLine { line } => assert_eq!(*line, 3),
            _ => panic!("Expected InsertBeforeLine"),
        }
    }

    #[test]
    fn test_parse_file_patch_json_replace_bytes() {
        use unfault_core::parse::ast::FileId;
        use unfault_core::types::{FilePatch, PatchHunk, PatchRange};

        let patch = FilePatch {
            file_id: FileId(1),
            hunks: vec![PatchHunk {
                range: PatchRange::ReplaceBytes { start: 10, end: 20 },
                replacement: "new_content".to_string(),
            }],
        };

        let json = serde_json::to_string(&patch).unwrap();
        let parsed: FilePatch = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.hunks.len(), 1);
        match &parsed.hunks[0].range {
            PatchRange::ReplaceBytes { start, end } => {
                assert_eq!(*start, 10);
                assert_eq!(*end, 20);
            }
            _ => panic!("Expected ReplaceBytes"),
        }
    }

    #[test]
    fn test_get_function_impact_request_serialization() {
        let req = GetFunctionImpactRequest {
            uri: "file:///path/to/file.py".to_string(),
            function_name: "my_func".to_string(),
            position: Position {
                line: 10,
                character: 0,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"functionName\":\"my_func\""));
        assert!(json.contains("\"uri\":\"file:///path/to/file.py\""));
    }

    #[test]
    fn test_get_function_impact_response_serialization() {
        let resp = GetFunctionImpactResponse {
            name: "my_func".to_string(),
            callers: vec![FunctionImpactCaller {
                name: "caller_func".to_string(),
                file: "main.py".to_string(),
                depth: 1,
                calls: Some("my_func".to_string()),
            }],
            routes: vec![FunctionImpactRoute {
                method: "POST".to_string(),
                path: "/api/test".to_string(),
                slos: None,
            }],
            findings: vec![FunctionImpactFinding {
                severity: "warning".to_string(),
                message: "Test finding".to_string(),
                learn_more: Some("https://example.com".to_string()),
            }],
            insights: vec![FunctionImpactInsight {
                severity: "warning".to_string(),
                message: "Friendly insight".to_string(),
            }],
            path_insights: vec![FunctionImpactInsight {
                severity: "error".to_string(),
                message: "Path insight from caller".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"name\":\"my_func\""));
        assert!(json.contains("\"callers\""));
        assert!(json.contains("\"caller_func\""));
        assert!(json.contains("\"routes\""));
        assert!(json.contains("\"POST\""));
        assert!(json.contains("\"findings\""));
        assert!(json.contains("\"learnMore\""));
        assert!(json.contains("\"insights\""));
        assert!(json.contains("\"pathInsights\""));
    }

    #[test]
    fn test_get_function_impact_response_deserialization() {
        let json = r#"{
            "name": "add",
            "callers": [{"name": "main", "file": "app.py", "depth": 1}],
            "routes": [{"method": "GET", "path": "/api"}],
            "findings": [{"severity": "error", "message": "issue", "learnMore": "http://x"}],
            "insights": [{"severity": "warning", "message": "Friendly insight"}],
            "pathInsights": [{"severity": "error", "message": "Path insight"}]
        }"#;
        let resp: GetFunctionImpactResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.name, "add");
        assert_eq!(resp.callers.len(), 1);
        assert_eq!(resp.callers[0].name, "main");
        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].method, "GET");
        assert_eq!(resp.findings.len(), 1);
        assert_eq!(resp.findings[0].learn_more, Some("http://x".to_string()));
        assert_eq!(resp.insights.len(), 1);
        assert_eq!(resp.insights[0].message, "Friendly insight");
        assert_eq!(resp.path_insights.len(), 1);
        assert_eq!(resp.path_insights[0].message, "Path insight");
    }
    
    #[test]
    fn test_summarize_findings() {
        // Test timeout detection
        let findings = vec![FunctionImpactFinding {
            severity: "warning".to_string(),
            message: "Missing timeout on HTTP call".to_string(),
            learn_more: None,
        }];
        let insights = summarize_findings(&findings);
        assert_eq!(insights.len(), 1);
        assert_eq!(insights[0].message, "Missing timeout on external call");
        
        // Test multiple categories
        let findings = vec![
            FunctionImpactFinding {
                severity: "warning".to_string(),
                message: "No timeout set".to_string(),
                learn_more: None,
            },
            FunctionImpactFinding {
                severity: "info".to_string(),
                message: "Missing retry logic".to_string(),
                learn_more: None,
            },
            FunctionImpactFinding {
                severity: "error".to_string(),
                message: "Security: SQL injection possible".to_string(),
                learn_more: None,
            },
        ];
        let insights = summarize_findings(&findings);
        assert!(insights.len() <= 3);
        assert!(insights.iter().any(|i| i.message.contains("timeout")));
        assert!(insights.iter().any(|i| i.message.contains("retry")));
        assert!(insights.iter().any(|i| i.message.contains("Security")));
        
        // Test empty findings
        let insights = summarize_findings(&[]);
        assert!(insights.is_empty());
    }

    #[test]
    fn test_normalize_severity() {
        assert_eq!(normalize_severity("critical"), "error");
        assert_eq!(normalize_severity("high"), "error");
        assert_eq!(normalize_severity("HIGH"), "error");
        assert_eq!(normalize_severity("medium"), "warning");
        assert_eq!(normalize_severity("MEDIUM"), "warning");
        assert_eq!(normalize_severity("low"), "info");
        assert_eq!(normalize_severity("info"), "info");
        assert_eq!(normalize_severity("unknown"), "info");
    }
}

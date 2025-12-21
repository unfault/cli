//! # LSP Server Command
//!
//! Implements the Language Server Protocol (LSP) server for IDE integration.
//! The LSP server provides real-time diagnostics and code actions by analyzing
//! code using the same client-side parsing approach as `unfault review`.
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
//! ## Custom Extensions
//!
//! The server supports custom LSP notifications:
//! - `unfault/fileCentrality`: Get file importance metrics for status bar display
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
use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tower_lsp::jsonrpc::Result as RpcResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::api::graph::{CentralityRequest, FileCentrality, IrFinding};
use crate::api::ApiClient;
use crate::config::Config;
use crate::exit_codes::*;
use crate::session::{build_ir_cached, compute_workspace_id, get_git_remote, WorkspaceScanner};

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
    /// Cached findings for code actions, keyed by document URI
    findings_cache: DashMap<Url, Vec<CachedFinding>>,
    /// Cached file centrality data for the workspace
    centrality_cache: Arc<tokio::sync::RwLock<Option<Vec<FileCentrality>>>>,
    /// Enable verbose logging
    verbose: bool,
}

impl UnfaultLsp {
    fn new(client: Client, verbose: bool) -> Self {
        let api_client = ApiClient::new(
            std::env::var("UNFAULT_API_URL")
                .unwrap_or_else(|_| "https://api.unfault.dev".to_string()),
        );

        Self {
            client,
            api_client: Arc::new(api_client),
            config: Config::load().ok(),
            workspace_root: Arc::new(tokio::sync::RwLock::new(None)),
            workspace_id: Arc::new(tokio::sync::RwLock::new(None)),
            findings_cache: DashMap::new(),
            centrality_cache: Arc::new(tokio::sync::RwLock::new(None)),
            verbose,
        }
    }

    /// Log a debug message if verbose mode is enabled
    fn log_debug(&self, message: &str) {
        if self.verbose {
            eprintln!("[unfault-lsp] {}", message);
        }
    }

    /// Analyze a document and publish diagnostics
    async fn analyze_document(&self, uri: &Url, text: &str, version: i32) {
        self.log_debug(&format!("Analyzing document: {}", uri));

        // Get workspace root
        let workspace_root = {
            let root = self.workspace_root.read().await;
            match root.as_ref() {
                Some(r) => r.clone(),
                None => {
                    self.log_debug("No workspace root set, skipping analysis");
                    return;
                }
            }
        };

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

        // Build IR for the workspace (cached)
        let build_result = match build_ir_cached(&workspace_root, None, self.verbose) {
            Ok(result) => result,
            Err(e) => {
                self.log_debug(&format!("Failed to build IR: {}", e));
                return;
            }
        };

        // Serialize IR
        let ir_json = match serde_json::to_string(&build_result.ir) {
            Ok(json) => json,
            Err(e) => {
                self.log_debug(&format!("Failed to serialize IR: {}", e));
                return;
            }
        };

        // Get workspace ID
        let workspace_id = {
            let id = self.workspace_id.read().await;
            match id.as_ref() {
                Some(id) => id.clone(),
                None => {
                    self.log_debug("No workspace ID, skipping analysis");
                    return;
                }
            }
        };

        // Detect profiles from workspace
        let mut scanner = WorkspaceScanner::new(&workspace_root);
        let workspace_info = match scanner.scan() {
            Ok(info) => info,
            Err(e) => {
                self.log_debug(&format!("Failed to scan workspace: {}", e));
                return;
            }
        };

        let profiles: Vec<String> = workspace_info
            .to_workspace_descriptor()
            .profiles
            .iter()
            .map(|p| p.id.clone())
            .collect();

        // Call API
        let workspace_label = workspace_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("workspace");

        let response = match self
            .api_client
            .analyze_ir(&api_key, &workspace_id, Some(workspace_label), &profiles, ir_json)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                self.log_debug(&format!("API error: {:?}", e));
                return;
            }
        };

        self.log_debug(&format!(
            "Analysis returned {} findings",
            response.findings.len()
        ));

        // Convert file path from URI to relative path
        let file_path = match uri.to_file_path() {
            Ok(path) => path
                .strip_prefix(&workspace_root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| path.to_string_lossy().to_string()),
            Err(_) => uri.path().to_string(),
        };

        // Filter findings for this document and convert to diagnostics
        let mut diagnostics = Vec::new();
        let mut cached_findings = Vec::new();

        for finding in &response.findings {
            // Check if this finding is for the current file
            if !finding.file_path.ends_with(&file_path) && !file_path.ends_with(&finding.file_path)
            {
                continue;
            }

            // Create diagnostic
            let diagnostic = self.finding_to_diagnostic(&finding, text);
            diagnostics.push(diagnostic);

            // Cache for code actions
            cached_findings.push(CachedFinding {
                finding: finding.clone(),
                version,
            });
        }

        // Store cached findings
        self.findings_cache.insert(uri.clone(), cached_findings);

        // Publish diagnostics
        let diagnostics_count = diagnostics.len();
        self.client
            .publish_diagnostics(uri.clone(), diagnostics, Some(version))
            .await;

        self.log_debug(&format!(
            "Published {} diagnostics for {}",
            diagnostics_count,
            uri
        ));
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
        let end_line = finding.end_line.map(|l| l.saturating_sub(1)).unwrap_or(start_line);
        let end_col = finding.end_column.map(|c| c.saturating_sub(1)).unwrap_or_else(|| {
            // If no end column, try to find the end of the line
            let lines: Vec<&str> = source_text.lines().collect();
            lines.get(end_line as usize).map(|l| l.len() as u32).unwrap_or(start_col + 10)
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
                character: finding.end_column.unwrap_or(finding.column + 10).saturating_sub(1),
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

            // Also check patch_json (newer format)
            if let Some(patch_json) = &finding.patch_json {
                // Try to parse patch_json and create workspace edit
                if let Ok(_patch_data) = serde_json::from_str::<serde_json::Value>(patch_json) {
                    // Handle the patch_json format if available
                    if let Some(preview) = &finding.fix_preview {
                        // Use fix_preview for the edit
                        let edit = self.create_edit_from_preview(uri, finding, preview, source_text);
                        if let Some(edit) = edit {
                            let action = CodeAction {
                                title: format!("Fix: {}", finding.title),
                                kind: Some(CodeActionKind::QUICKFIX),
                                diagnostics: Some(vec![
                                    self.finding_to_diagnostic(finding, source_text)
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

    /// Create a workspace edit from a fix preview
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
        let end_col = finding.end_column.unwrap_or(finding.column + 10).saturating_sub(1);

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
                if let Some(centrality) = centralities.iter().find(|c| {
                    c.path.ends_with(file_path) || file_path.ends_with(&c.path)
                }) {
                    let total_files = centralities.len() as i32;
                    return Some(self.centrality_to_notification(centrality, total_files));
                }
            }
        }

        // Fetch from API
        let request = CentralityRequest {
            session_id: None,
            workspace_id: Some(workspace_id),
            limit: 50,  // Get top 50 files
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
}

/// Check if two ranges overlap
fn ranges_overlap(a: &Range, b: &Range) -> bool {
    !(a.end.line < b.start.line
        || (a.end.line == b.start.line && a.end.character < b.start.character)
        || b.end.line < a.start.line
        || (b.end.line == a.start.line && b.end.character < a.start.character))
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

                let workspace_id_result = compute_workspace_id(
                    git_remote.as_deref(),
                    None,
                    workspace_label.as_deref(),
                );

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

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                // We use the "push" model via publishDiagnostics, not the "pull" model
                // Do NOT set diagnostic_provider as that enables textDocument/diagnostic requests
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
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

    async fn shutdown(&self) -> RpcResult<()> {
        self.log_debug("LSP shutdown");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.log_debug(&format!("Document opened: {}", params.text_document.uri));

        self.analyze_document(
            &params.text_document.uri,
            &params.text_document.text,
            params.text_document.version,
        )
        .await;

        // Send file centrality notification
        if let Ok(path) = params.text_document.uri.to_file_path() {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if let Some(centrality) = self.get_file_centrality(file_name).await {
                // Send custom notification
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
        if let Some(change) = params.content_changes.last() {
            self.analyze_document(
                &params.text_document.uri,
                &change.text,
                params.text_document.version,
            )
            .await;
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        self.log_debug(&format!("Document saved: {}", params.text_document.uri));

        // Re-analyze on save with saved text if available
        if let Some(text) = params.text {
            self.analyze_document(&params.text_document.uri, &text, 0).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.log_debug(&format!("Document closed: {}", params.text_document.uri));

        // Clear cached findings
        self.findings_cache.remove(&params.text_document.uri);

        // Clear diagnostics
        self.client
            .publish_diagnostics(params.text_document.uri, vec![], None)
            .await;
    }

    async fn code_action(&self, params: CodeActionParams) -> RpcResult<Option<CodeActionResponse>> {
        self.log_debug(&format!("Code action requested for: {}", params.text_document.uri));

        // We need the document text to generate edits
        // Since we don't store it, we'll use the diagnostics range
        let actions = self.get_code_actions_for_range(
            &params.text_document.uri,
            &params.range,
            "", // We'll need to handle this properly with document storage
        );

        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(actions.into_iter().map(CodeActionOrCommand::CodeAction).collect()))
        }
    }
}

/// Custom notification type for file centrality
struct FileCentralityNotificationType;

impl tower_lsp::lsp_types::notification::Notification for FileCentralityNotificationType {
    type Params = FileCentralityNotification;
    const METHOD: &'static str = "unfault/fileCentrality";
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

    let (service, socket) = LspService::new(|client| UnfaultLsp::new(client, args.verbose));

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(EXIT_SUCCESS)
}

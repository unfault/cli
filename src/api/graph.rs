//! # Graph API
//!
//! This module contains all API endpoints and types related to the code graph
//! for impact analysis, dependency queries, and centrality analysis.
//!
//! ## Endpoints
//!
//! - `POST /api/v1/graph/ingest` - Ingest full graph stream (chunked)
//! - `POST /api/v1/graph/analyze` - Analyze semantics with rules (no graph payload)
//! - `POST /api/v1/graph/impact` - Impact analysis ("What breaks if I change X?")
//! - `POST /api/v1/graph/dependencies` - Dependency queries
//! - `POST /api/v1/graph/centrality` - Centrality analysis ("What are the most critical files?")
//! - `GET /api/v1/graph/stats/{session_id}` - Graph statistics
//!
//! ## Note
//!
//! The code graph is ingested via `/api/v1/graph/ingest` and then the CLI sends
//! the per-file semantics via `/api/v1/graph/analyze` for rule evaluation.

use crate::api::client::{ApiClient, ApiError};
use log::debug;
use serde::{Deserialize, Serialize};
use tower_lsp::lsp_types::Range;

// =============================================================================
// Request Types
// =============================================================================

/// Request for impact analysis: "What breaks if I change this file?"
///
/// Either `session_id` or `workspace_id` must be provided. If `workspace_id` is used,
/// the API automatically resolves to the latest session with graph data.
///
/// # Example
///
/// ```rust
/// use unfault::api::graph::ImpactAnalysisRequest;
///
/// // Using workspace_id (recommended)
/// let request = ImpactAnalysisRequest {
///     session_id: None,
///     workspace_id: Some("wks_abc123".to_string()),
///     file_path: "auth/middleware.py".to_string(),
///     max_depth: 5,
/// };
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ImpactAnalysisRequest {
    /// Analysis session ID (UUID) - optional if workspace_id is provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Workspace ID (auto-resolves to latest session with graph)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Path to the file to analyze
    pub file_path: String,
    /// Maximum import hops to traverse (1-10, default: 5)
    pub max_depth: i32,
}

/// Request for dependency queries
///
/// Supports two query types:
/// - `files_using_library`: Find all files using a specific library
/// - `external_dependencies`: Find all external deps for a file
///
/// Either `session_id` or `workspace_id` must be provided.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyQueryRequest {
    /// Analysis session ID (UUID) - optional if workspace_id is provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Workspace ID (auto-resolves to latest session with graph)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Query type: "files_using_library" or "external_dependencies"
    pub query_type: String,
    /// Library name (required for files_using_library)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_name: Option<String>,
    /// File path (required for external_dependencies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

/// Request for centrality analysis: "What are the most critical files?"
///
/// Either `session_id` or `workspace_id` must be provided.
#[derive(Debug, Clone, Serialize)]
pub struct CentralityRequest {
    /// Analysis session ID (UUID) - optional if workspace_id is provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Workspace ID (auto-resolves to latest session with graph)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Maximum number of files to return (1-50, default: 10)
    pub limit: i32,
    /// Metric to sort by (in_degree, out_degree, total_degree, library_usage, importance_score)
    pub sort_by: String,
}

// =============================================================================
// IR Analysis Types (Client-Side Parsing)
// =============================================================================

/// Request to analyze code using client-side parsed Intermediate Representation.
///
/// This is the new architecture where:
/// 1. CLI parses code locally and builds semantics + graph
/// 2. Serialized IR is sent to the API (no source code over the wire)
/// 3. API runs rules and returns findings
///
/// # Example
///
/// ```rust,ignore
/// use unfault::api::graph::IrAnalyzeRequest;
/// use unfault::session::ir_builder::build_ir;
///
/// let ir = build_ir(&workspace_path, &files)?;
/// let request = IrAnalyzeRequest {
///     session_id: "...".to_string(),
///     profiles: vec!["stability".to_string()],
///     semantics_json: serde_json::to_string(&ir.semantics)?,
/// };
/// let response = client.analyze_ir(&api_key, &request).await?;
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct IrAnalyzeRequest {
    /// Session ID returned by POST /api/v1/graph/ingest
    pub session_id: String,
    /// Profiles to use for analysis (e.g., ["stability", "security"])
    pub profiles: Vec<String>,
    /// JSON-serialized semantics array from unfault-core IR
    pub semantics_json: String,
}

/// A single finding from rule evaluation (API response format)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IrFinding {
    /// Rule ID that generated this finding
    pub rule_id: String,
    /// Title of the finding
    #[serde(default)]
    pub title: String,
    /// Detailed description
    #[serde(default)]
    pub description: String,
    /// Severity level (Info, Low, Medium, High, Critical)
    pub severity: String,
    /// Category/dimension (Stability, Performance, etc.)
    #[serde(default)]
    pub dimension: String,
    /// File path where the issue was found
    pub file_path: String,
    /// Line number (1-indexed) - optional for backwards compatibility
    #[serde(default)]
    pub line: u32,
    /// Column number (1-indexed)
    #[serde(default)]
    pub column: u32,
    /// End line (1-indexed)
    #[serde(default)]
    pub end_line: Option<u32>,
    /// End column (1-indexed)
    #[serde(default)]
    pub end_column: Option<u32>,
    /// Human-readable description of the issue (alias for backwards compat)
    #[serde(default)]
    pub message: String,
    /// JSON-serialized patch for client-side application
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_json: Option<String>,
    /// Human-readable fix preview
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_preview: Option<String>,
    /// Legacy: Suggested fix patch (unified diff format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    /// Byte offset start (for precise patching)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_start: Option<usize>,
    /// Byte offset end (for precise patching)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_end: Option<usize>,
}

/// Response from starting a resumable graph ingest
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphIngestStartResponse {
    pub session_id: String,
}

/// Response from ingest status endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphIngestStatusResponse {
    pub session_id: String,
    pub phase: String,
    pub nodes_next_seq: i64,
    pub edges_next_seq: i64,
    pub nodes_received: i64,
    pub edges_received: i64,
}

pub struct GraphIngestResponse {
    pub session_id: String,
    pub nodes_created: i64,
    pub edges_created: i64,
    pub elapsed_ms: i64,
}

/// Progress snapshot for graph ingestion.
#[derive(Debug, Clone)]
pub struct GraphIngestProgress {
    /// Current ingest phase (nodes/edges/done)
    pub phase: String,
    /// Completion percentage [0, 100]
    pub percent: u8,
    /// Nodes received so far
    pub nodes_received: i64,
    /// Edges received so far
    pub edges_received: i64,
    /// Total nodes to ingest
    pub nodes_total: i64,
    /// Total edges to ingest
    pub edges_total: i64,
}

fn compute_ingest_percent(
    nodes_total: i64,
    edges_total: i64,
    nodes_received: i64,
    edges_received: i64,
) -> u8 {
    let total = nodes_total.saturating_add(edges_total);
    if total <= 0 {
        return 100;
    }
    let done = nodes_received
        .saturating_add(edges_received)
        .clamp(0, total);
    ((done.saturating_mul(100)) / total).clamp(0, 100) as u8
}

/// Response from IR analysis endpoint (matches API IrAnalysisResponse)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IrAnalyzeResponse {
    /// List of findings from rule evaluation
    pub findings: Vec<IrFinding>,
    /// Number of files analyzed
    pub file_count: i32,
    /// Processing time in milliseconds
    pub elapsed_ms: i64,
    /// Graph statistics after rebuild
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_stats: Option<IrGraphStats>,
}

// =============================================================================
// Chunked Semantics Analysis Types
// =============================================================================

/// Request to start chunked semantics analysis
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeStartRequest {
    /// Session ID created by POST /api/v1/graph/ingest
    pub session_id: String,
    /// Optional list of rule IDs to run
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_ids: Option<Vec<String>>,
    /// Optional list of profiles to resolve to rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<String>>,
}

/// Response from starting chunked analysis
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalyzeStartResponse {
    pub session_id: String,
    pub next_seq: i64,
}

/// Response from uploading an analysis chunk
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalyzeChunkResponse {
    pub session_id: String,
    pub seq: i64,
    pub next_seq: i64,
    pub files_processed_total: i64,
    pub findings_added_in_chunk: i64,
    pub findings_total_so_far: i64,
}

/// Response from analysis status endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalyzeStatusResponse {
    pub session_id: String,
    pub next_seq: i64,
    pub files_processed_total: i64,
    pub findings_total_so_far: i64,
}

/// Response from finalizing chunked analysis
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalyzeFinalizeResponse {
    pub session_id: String,
    pub files_processed_total: i64,
    pub findings_total_so_far: i64,
}

/// Graph statistics from IR analysis (matches API IrGraphStats)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IrGraphStats {
    /// Number of file nodes
    pub file_count: i32,
    /// Number of function nodes
    pub function_count: i32,
    /// Number of class nodes
    pub class_count: i32,
    /// Number of external library nodes
    pub external_module_count: i32,
    /// Number of import edges
    pub import_edge_count: i32,
    /// Number of contains edges
    pub contains_edge_count: i32,
    /// Number of uses_library edges
    pub uses_library_edge_count: i32,
    /// Total number of nodes
    pub total_nodes: i32,
    /// Total number of edges
    pub total_edges: i32,
}

// =============================================================================
// Response Types
// =============================================================================

/// Information about a file in the code graph
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileInfo {
    /// Path to the file relative to workspace root
    pub path: String,
    /// Programming language of the file (e.g., "Python", "Go")
    pub language: Option<String>,
    /// Distance from the target file (for transitive queries)
    pub depth: Option<i32>,
}

/// Information about a function in a file (for LSP hover/navigation)
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name (qualified if method)
    pub name: String,
    /// LSP range where the function is defined
    pub range: Range,
}

/// Information about an external library/module
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalModuleInfo {
    /// Name of the library (e.g., "requests", "fastapi")
    pub name: String,
    /// Category of the library (e.g., "HttpClient", "Database")
    pub category: Option<String>,
}

/// Response for impact analysis query
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImpactAnalysisResponse {
    /// The file being analyzed
    pub file_path: String,
    /// Files that directly import this file
    pub direct_importers: Vec<FileInfo>,
    /// All files affected (including direct)
    pub transitive_importers: Vec<FileInfo>,
    /// Total number of affected files
    pub total_affected: i32,
}

/// Response for dependency queries
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DependencyQueryResponse {
    /// The query type executed
    pub query_type: String,
    /// Files matching the query (for files_using_library)
    pub files: Option<Vec<FileInfo>>,
    /// External dependencies (for external_dependencies)
    pub dependencies: Option<Vec<ExternalModuleInfo>>,
}

/// Centrality metrics for a single file
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileCentrality {
    /// Path to the file
    pub path: String,
    /// Number of files that import this file
    pub in_degree: i32,
    /// Number of files this file imports
    pub out_degree: i32,
    /// Sum of in and out degrees
    pub total_degree: i32,
    /// Number of external libraries used
    pub library_usage: i32,
    /// Weighted importance score (higher = more critical)
    pub importance_score: i32,
}

/// Response for centrality analysis query
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CentralityResponse {
    /// Files with centrality metrics, sorted by requested metric
    pub files: Vec<FileCentrality>,
    /// Total number of files in the graph
    pub total_files: i32,
    /// The metric used for sorting
    pub sort_by: String,
}

/// Statistics about the code graph for a session
#[derive(Debug, Clone, Serialize)]
pub struct FunctionImpactRequest {
    /// Analysis session ID (UUID) - optional if workspace_id is provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Workspace ID (auto-resolves to latest session with graph)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Stable file identifier (uf:file:v1:...). Preferred over file_path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    /// Path to the file containing the function (legacy fallback)
    pub file_path: String,
    /// Name of the function (qualified if method)
    pub function_name: String,
    /// Maximum call hops to traverse (1-10, default: 5)
    pub max_depth: i32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionCaller {
    /// Path to the file containing the caller
    pub path: String,
    /// Name of the calling function
    pub function: String,
    /// Distance from the target function
    pub depth: i32,
    /// Whether this caller is an HTTP route handler
    #[serde(default)]
    pub is_route_handler: bool,
    /// The route path if this is a route handler (e.g., "/api/webhooks")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_path: Option<String>,
    /// HTTP method if this is a route handler (e.g., "POST", "GET")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionFinding {
    /// Rule ID that generated this finding
    pub rule_id: String,
    /// Title of the finding
    pub title: String,
    /// Description of the finding
    pub description: String,
    /// Severity level
    pub severity: String,
    /// Dimension/category
    pub dimension: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrameworkReference {
    /// Type of reference (e.g., "lifespan", "on_startup")
    pub reference_type: String,
    /// Framework name (e.g., "FastAPI")
    pub framework: String,
    /// File containing the framework usage
    pub source_file: String,
    /// Variable name of the app (e.g., "app")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_var: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionImpactResponse {
    /// The function being analyzed (file:function)
    pub function: String,
    /// Functions that directly call this function
    #[serde(default)]
    pub direct_callers: Vec<FunctionCaller>,
    /// All functions affected via calls (including direct)
    #[serde(default)]
    pub transitive_callers: Vec<FunctionCaller>,
    /// Functions that directly use this function as a dependency (e.g., FastAPI Depends)
    #[serde(default)]
    pub direct_dependency_consumers: Vec<FunctionCaller>,
    /// All functions affected via dependency injection (including direct)
    #[serde(default)]
    pub transitive_dependency_consumers: Vec<FunctionCaller>,
    /// Framework-level references (lifespan handlers, event handlers, etc.)
    #[serde(default)]
    pub framework_references: Vec<FrameworkReference>,
    /// Total number of affected functions
    pub total_affected: i32,
    /// Findings related to this function
    #[serde(default)]
    pub findings: Vec<FunctionFinding>,
    /// Summary of the function's impact context
    #[serde(default)]
    pub impact_summary: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphStatsResponse {
    /// Number of file nodes
    pub file_count: i32,
    /// Number of function nodes
    pub function_count: i32,
    /// Number of class nodes
    pub class_count: i32,
    /// Number of external library nodes
    pub external_module_count: i32,
    /// Total number of nodes
    pub total_nodes: i32,
    /// Number of import edges
    pub imports_edge_count: i32,
    /// Number of contains edges
    pub contains_edge_count: i32,
    /// Number of uses_library edges
    pub uses_library_edge_count: i32,
    /// Number of calls edges
    pub calls_edge_count: i32,
    /// Total number of edges
    pub total_edges: i32,
}

// =============================================================================
// API Client Methods
// =============================================================================

/// Convert a reqwest error to an ApiError
fn to_network_error(err: reqwest::Error) -> ApiError {
    ApiError::Network {
        message: err.to_string(),
    }
}

/// Convert an HTTP response with error status to an ApiError
fn to_http_error(status: reqwest::StatusCode, error_text: String) -> ApiError {
    let status_code = status.as_u16();

    match status_code {
        401 => ApiError::Unauthorized {
            message: if error_text.is_empty() {
                "Invalid or expired API key".to_string()
            } else {
                error_text
            },
        },
        403 => ApiError::Forbidden {
            message: if error_text.is_empty() {
                "Access denied".to_string()
            } else {
                error_text
            },
        },
        404 => ApiError::ClientError {
            status: status_code,
            message: if error_text.is_empty() {
                "Resource not found".to_string()
            } else {
                error_text
            },
        },
        500..=599 => ApiError::Server {
            status: status_code,
            message: if error_text.is_empty() {
                format!("Server error ({})", status_code)
            } else {
                error_text
            },
        },
        _ => ApiError::ClientError {
            status: status_code,
            message: if error_text.is_empty() {
                format!("Request failed ({})", status_code)
            } else {
                error_text
            },
        },
    }
}

impl ApiClient {
    /// Query impact analysis: "What breaks if I change this file?"
    pub async fn graph_impact(
        &self,
        api_key: &str,
        request: &ImpactAnalysisRequest,
    ) -> Result<ImpactAnalysisResponse, ApiError> {
        let url = format!("{}/api/v1/graph/impact", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        debug!(
            "[API] Response status: {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            debug!("[API] Error response body: {}", error_text);
            return Err(to_http_error(status, error_text));
        }

        let impact_response: ImpactAnalysisResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse impact response: {}", e),
            })?;

        Ok(impact_response)
    }

    /// Query code dependencies
    pub async fn graph_dependencies(
        &self,
        api_key: &str,
        request: &DependencyQueryRequest,
    ) -> Result<DependencyQueryResponse, ApiError> {
        let url = format!("{}/api/v1/graph/dependencies", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        debug!(
            "[API] Response status: {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            debug!("[API] Error response body: {}", error_text);
            return Err(to_http_error(status, error_text));
        }

        let dependency_response: DependencyQueryResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse dependency response: {}", e),
            })?;

        Ok(dependency_response)
    }

    /// Query centrality analysis: "What are the most critical files?"
    pub async fn graph_centrality(
        &self,
        api_key: &str,
        request: &CentralityRequest,
    ) -> Result<CentralityResponse, ApiError> {
        let url = format!("{}/api/v1/graph/centrality", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        debug!(
            "[API] Response status: {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            debug!("[API] Error response body: {}", error_text);
            return Err(to_http_error(status, error_text));
        }

        let centrality_response: CentralityResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse centrality response: {}", e),
            })?;

        Ok(centrality_response)
    }

    /// Query function impact analysis: "What breaks if I change this function?"
    pub async fn graph_function_impact(
        &self,
        api_key: &str,
        request: &FunctionImpactRequest,
    ) -> Result<FunctionImpactResponse, ApiError> {
        let url = format!("{}/api/v1/graph/function_impact", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        debug!(
            "[API] Response status: {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            debug!("[API] Error response body: {}", error_text);
            return Err(to_http_error(status, error_text));
        }

        // Get the response text for debugging
        let response_text = response.text().await.unwrap_or_default();
        debug!("[API] Function impact response body: {}", response_text);

        let impact_response: FunctionImpactResponse = serde_json::from_str(&response_text)
            .map_err(|e| ApiError::ParseError {
                message: format!(
                    "Failed to parse function impact response: {} (body: {})",
                    e,
                    response_text.chars().take(200).collect::<String>()
                ),
            })?;

        Ok(impact_response)
    }

    /// Get statistics about the code graph for a session
    pub async fn graph_stats(
        &self,
        api_key: &str,
        session_id: &str,
    ) -> Result<GraphStatsResponse, ApiError> {
        let url = format!("{}/api/v1/graph/stats/{}", self.base_url, session_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        debug!(
            "[API] Response status: {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            debug!("[API] Error response body: {}", error_text);
            return Err(to_http_error(status, error_text));
        }

        let stats_response: GraphStatsResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse stats response: {}", e),
            })?;

        Ok(stats_response)
    }

    /// Get statistics about the code graph for a workspace
    ///
    /// This automatically resolves to the latest session with graph data.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `workspace_id` - Workspace ID (computed from git remote or manifest)
    ///
    /// # Returns
    ///
    /// * `Ok(GraphStatsResponse)` - Statistics retrieved
    /// * `Err(ApiError)` - Request failed (404 if no graph data found)
    pub async fn graph_stats_by_workspace(
        &self,
        api_key: &str,
        workspace_id: &str,
    ) -> Result<GraphStatsResponse, ApiError> {
        let url = format!(
            "{}/api/v1/graph/stats?workspace_id={}",
            self.base_url,
            urlencoding::encode(workspace_id)
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        debug!(
            "[API] Response status: {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            debug!("[API] Error response body: {}", error_text);
            return Err(to_http_error(status, error_text));
        }

        let stats_response: GraphStatsResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse stats response: {}", e),
            })?;

        Ok(stats_response)
    }

    /// Ingest a full code graph into the API.
    ///
    /// The body is streamed as zstd-compressed NDJSON to avoid materializing the
    /// full graph payload in memory.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `workspace_id` - Workspace ID
    /// * `workspace_label` - Workspace label
    /// * `graph` - In-memory graph built by unfault-core
    ///
    /// # Returns
    ///
    /// * `Ok(GraphIngestResponse)` - Ingestion completed with session_id
    /// * `Err(ApiError)` - Request failed
    async fn ingest_status(
        &self,
        api_key: &str,
        session_id: &str,
    ) -> Result<GraphIngestStatusResponse, ApiError> {
        let url = format!(
            "{}/api/v1/graph/ingest/status?session_id={}",
            self.base_url,
            urlencoding::encode(session_id)
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(to_http_error(status, error_text));
        }

        response.json().await.map_err(|e| ApiError::ParseError {
            message: format!("Failed to parse ingest status response: {}", e),
        })
    }

    pub async fn ingest_graph(
        &self,
        api_key: &str,
        workspace_id: &str,
        workspace_label: Option<&str>,
        git_remote: Option<&str>,
        graph: unfault_core::graph::CodeGraph,
    ) -> Result<GraphIngestResponse, ApiError> {
        self.ingest_graph_with_progress(
            api_key,
            workspace_id,
            workspace_label,
            git_remote,
            graph,
            |_| {},
        )
        .await
    }

    /// Ingest a full code graph into the API, reporting progress snapshots.
    ///
    /// This is identical to `ingest_graph` but calls `on_progress` after each
    /// accepted chunk (and after state refreshes), allowing the CLI to show
    /// a percentage to users.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API authentication key
    /// * `workspace_id` - Workspace identifier (e.g., "wks_abc123...")
    /// * `workspace_label` - Human-readable workspace label
    /// * `git_remote` - Git remote URL for computing stable file IDs. If provided,
    ///   file IDs will be globally unique across machines for the same repo.
    /// * `graph` - The code graph to ingest
    /// * `on_progress` - Progress callback
    pub async fn ingest_graph_with_progress<F>(
        &self,
        api_key: &str,
        workspace_id: &str,
        workspace_label: Option<&str>,
        git_remote: Option<&str>,
        graph: unfault_core::graph::CodeGraph,
        mut on_progress: F,
    ) -> Result<GraphIngestResponse, ApiError>
    where
        F: FnMut(GraphIngestProgress),
    {
        use crate::api::graph_stream::{IdContext, encode_edges_chunk, encode_nodes_chunk};

        let t0 = std::time::Instant::now();

        // Create ID context for computing stable node identifiers
        let mut id_ctx = IdContext::new(
            &graph,
            git_remote.map(|s| s.to_string()),
            workspace_id.to_string(),
        );

        let start_url = format!(
            "{}/api/v1/graph/ingest/start?workspace_id={}&workspace_label={}",
            self.base_url,
            urlencoding::encode(workspace_id),
            urlencoding::encode(workspace_label.unwrap_or("")),
        );

        let start_resp = self
            .client
            .post(&start_url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Length", 0)
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(to_network_error)?;

        let http_status = start_resp.status();
        if !http_status.is_success() {
            let error_text = start_resp.text().await.unwrap_or_default();
            return Err(to_http_error(http_status, error_text));
        }

        let start: GraphIngestStartResponse =
            start_resp.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse ingest start response: {}", e),
            })?;

        let session_id = start.session_id;

        const NODE_CHUNK: usize = 50_000;
        const EDGE_CHUNK: usize = 200_000;

        let node_total = graph.graph.node_count() as i64;
        let edge_total = graph.graph.edge_count() as i64;

        let mut report = |status: &GraphIngestStatusResponse| {
            let percent = compute_ingest_percent(
                node_total,
                edge_total,
                status.nodes_received,
                status.edges_received,
            );
            on_progress(GraphIngestProgress {
                phase: status.phase.clone(),
                percent,
                nodes_received: status.nodes_received,
                edges_received: status.edges_received,
                nodes_total: node_total,
                edges_total: edge_total,
            });
        };

        let mut ingest_status = self.ingest_status(api_key, &session_id).await?;
        report(&ingest_status);

        // Upload nodes (resume on 409 or transient request failures)
        while ingest_status.phase == "nodes" {
            let next_seq = ingest_status.nodes_next_seq.max(0) as usize;
            let start_idx = next_seq.saturating_mul(NODE_CHUNK);
            if start_idx >= node_total.max(0) as usize {
                break;
            }

            let chunk_bytes =
                encode_nodes_chunk(&graph, &mut id_ctx, start_idx, NODE_CHUNK, next_seq as u32)
                    .map_err(|e| ApiError::Network {
                        message: format!("Failed to encode node chunk: {}", e),
                    })?;

            let chunk_url = format!(
                "{}/api/v1/graph/ingest/chunk?session_id={}&phase=nodes&seq={}",
                self.base_url,
                urlencoding::encode(&session_id),
                next_seq
            );

            let resp = match self
                .client
                .post(&chunk_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/x-msgpack")
                .header("Content-Encoding", "zstd")
                .body(chunk_bytes)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    ingest_status = self.ingest_status(api_key, &session_id).await?;
                    report(&ingest_status);
                    continue;
                }
            };

            let http_status = resp.status();
            if http_status.as_u16() == 409 {
                ingest_status = self.ingest_status(api_key, &session_id).await?;
                report(&ingest_status);
                continue;
            }

            if !http_status.is_success() {
                let error_text = resp.text().await.unwrap_or_default();
                return Err(to_http_error(http_status, error_text));
            }

            ingest_status = self.ingest_status(api_key, &session_id).await?;
            report(&ingest_status);
        }

        ingest_status = self.ingest_status(api_key, &session_id).await?;
        report(&ingest_status);

        // Transition nodes → edges if needed
        if ingest_status.phase == "nodes" {
            let trans_url = format!(
                "{}/api/v1/graph/ingest/transition?session_id={}&to_phase=edges",
                self.base_url,
                urlencoding::encode(&session_id)
            );

            let resp = self
                .client
                .post(&trans_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Length", 0)
                .body(Vec::<u8>::new())
                .send()
                .await
                .map_err(to_network_error)?;

            let http_status = resp.status();
            if !http_status.is_success() {
                let error_text = resp.text().await.unwrap_or_default();
                return Err(to_http_error(http_status, error_text));
            }

            ingest_status = self.ingest_status(api_key, &session_id).await?;
            report(&ingest_status);
        }

        // Upload edges
        while ingest_status.phase == "edges" {
            let next_seq = ingest_status.edges_next_seq.max(0) as usize;
            let start_idx = next_seq.saturating_mul(EDGE_CHUNK);
            if start_idx >= edge_total.max(0) as usize {
                break;
            }

            let chunk_bytes =
                encode_edges_chunk(&graph, &mut id_ctx, start_idx, EDGE_CHUNK, next_seq as u32)
                    .map_err(|e| ApiError::Network {
                        message: format!("Failed to encode edge chunk: {}", e),
                    })?;

            let chunk_url = format!(
                "{}/api/v1/graph/ingest/chunk?session_id={}&phase=edges&seq={}",
                self.base_url,
                urlencoding::encode(&session_id),
                next_seq
            );

            let resp = match self
                .client
                .post(&chunk_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/x-msgpack")
                .header("Content-Encoding", "zstd")
                .body(chunk_bytes)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    ingest_status = self.ingest_status(api_key, &session_id).await?;
                    report(&ingest_status);
                    continue;
                }
            };

            let http_status = resp.status();
            if http_status.as_u16() == 409 {
                ingest_status = self.ingest_status(api_key, &session_id).await?;
                report(&ingest_status);
                continue;
            }

            if !http_status.is_success() {
                let error_text = resp.text().await.unwrap_or_default();
                return Err(to_http_error(http_status, error_text));
            }

            ingest_status = self.ingest_status(api_key, &session_id).await?;
            report(&ingest_status);
        }

        ingest_status = self.ingest_status(api_key, &session_id).await?;
        report(&ingest_status);

        // Transition edges → done if needed
        if ingest_status.phase == "edges" {
            let done_url = format!(
                "{}/api/v1/graph/ingest/transition?session_id={}&to_phase=done",
                self.base_url,
                urlencoding::encode(&session_id)
            );

            let resp = self
                .client
                .post(&done_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Length", 0)
                .body(Vec::<u8>::new())
                .send()
                .await
                .map_err(to_network_error)?;

            let http_status = resp.status();
            if !http_status.is_success() {
                let error_text = resp.text().await.unwrap_or_default();
                return Err(to_http_error(http_status, error_text));
            }

            ingest_status = self.ingest_status(api_key, &session_id).await?;
            report(&ingest_status);
        }

        Ok(GraphIngestResponse {
            session_id,
            nodes_created: node_total,
            edges_created: edge_total,
            elapsed_ms: t0.elapsed().as_millis() as i64,
        })
    }

    /// Analyze code using client-side parsed semantics.
    ///
    /// The graph must have already been ingested via `ingest_graph`.
    pub async fn analyze_ir(
        &self,
        api_key: &str,
        session_id: &str,
        profiles: &[String],
        semantics_json: String,
    ) -> Result<IrAnalyzeResponse, ApiError> {
        let url = format!("{}/api/v1/graph/analyze", self.base_url);

        let request = IrAnalyzeRequest {
            session_id: session_id.to_string(),
            profiles: profiles.to_vec(),
            semantics_json,
        };

        debug!("[API] Sending POST request...");

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        debug!(
            "[API] Response status: {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            debug!("[API] Error response body: {}", error_text);
            return Err(to_http_error(status, error_text));
        }

        let analyze_response: IrAnalyzeResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse IR analysis response: {}", e),
            })?;

        debug!("[API] === Received IR Analysis Response ===");
        debug!("[API] File count: {}", analyze_response.file_count);
        debug!("[API] Processing time: {}ms", analyze_response.elapsed_ms);
        debug!("[API] Findings count: {}", analyze_response.findings.len());

        if let Some(ref graph_stats) = analyze_response.graph_stats {
            debug!("[API] Graph statistics from API:");
            debug!("  - Total nodes: {}", graph_stats.total_nodes);
            debug!("  - Total edges: {}", graph_stats.total_edges);
            debug!("  - Files: {}", graph_stats.file_count);
            debug!("  - Functions: {}", graph_stats.function_count);
            debug!("  - Classes: {}", graph_stats.class_count);
            debug!(
                "  - External modules: {}",
                graph_stats.external_module_count
            );
            debug!("  - Import edges: {}", graph_stats.import_edge_count);
            debug!("  - Contains edges: {}", graph_stats.contains_edge_count);
            debug!(
                "  - Uses library edges: {}",
                graph_stats.uses_library_edge_count
            );
        }

        if !analyze_response.findings.is_empty() {
            debug!("[API] First 5 findings:");
            for (i, finding) in analyze_response.findings.iter().take(5).enumerate() {
                debug!(
                    "  {}. {} ({}) at {}:{}:{}",
                    i + 1,
                    finding.rule_id,
                    finding.severity,
                    finding.file_path,
                    finding.line,
                    finding.column
                );
                debug!("     Title: {}", finding.title);
                debug!("     Dimension: {}", finding.dimension);
                if finding.patch_json.is_some() || finding.patch.is_some() {
                    debug!("     Has patch: Yes");
                }
            }
            if analyze_response.findings.len() > 5 {
                debug!(
                    "  ... and {} more findings",
                    analyze_response.findings.len() - 5
                );
            }
        }

        Ok(analyze_response)
    }

    // =========================================================================
    // Chunked Semantics Analysis Methods
    // =========================================================================

    /// Start a chunked semantics analysis session.
    ///
    /// This initializes analysis state for streaming semantics to the server.
    /// Call this after `ingest_graph` and before sending semantics chunks.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `session_id` - Session ID from graph ingest
    /// * `profiles` - List of profiles to resolve to rules (e.g., ["stability"])
    ///
    /// # Returns
    ///
    /// * `Ok(AnalyzeStartResponse)` - Contains next_seq for first chunk
    /// * `Err(ApiError)` - Request failed
    pub async fn analyze_start(
        &self,
        api_key: &str,
        session_id: &str,
        profiles: &[String],
    ) -> Result<AnalyzeStartResponse, ApiError> {
        let url = format!("{}/api/v1/graph/analyze/start", self.base_url);

        let request = AnalyzeStartRequest {
            session_id: session_id.to_string(),
            rule_ids: None,
            profiles: if profiles.is_empty() {
                None
            } else {
                Some(profiles.to_vec())
            },
        };

        debug!("[API] Starting chunked analysis for session {}", session_id);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(to_http_error(status, error_text));
        }

        response.json().await.map_err(|e| ApiError::ParseError {
            message: format!("Failed to parse analyze start response: {}", e),
        })
    }

    /// Get the current status of a chunked analysis.
    ///
    /// Use this to check progress or resume after a failed chunk upload.
    pub async fn analyze_status(
        &self,
        api_key: &str,
        session_id: &str,
    ) -> Result<AnalyzeStatusResponse, ApiError> {
        let url = format!(
            "{}/api/v1/graph/analyze/status?session_id={}",
            self.base_url,
            urlencoding::encode(session_id)
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(to_http_error(status, error_text));
        }

        response.json().await.map_err(|e| ApiError::ParseError {
            message: format!("Failed to parse analyze status response: {}", e),
        })
    }

    /// Upload a chunk of semantics for analysis.
    ///
    /// Each chunk is zstd-compressed framed msgpack containing per-file semantics
    /// records and a final control record with checksum.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `session_id` - Session ID from graph ingest
    /// * `seq` - Chunk sequence number (must match server's expected next_seq)
    /// * `chunk_data` - Compressed chunk bytes from `encode_semantics_chunk`
    ///
    /// # Returns
    ///
    /// * `Ok(AnalyzeChunkResponse)` - Contains updated findings count
    /// * `Err(ApiError)` - Request failed (409 if seq mismatch)
    pub async fn analyze_chunk(
        &self,
        api_key: &str,
        session_id: &str,
        seq: u32,
        chunk_data: Vec<u8>,
    ) -> Result<AnalyzeChunkResponse, ApiError> {
        let url = format!(
            "{}/api/v1/graph/analyze/chunk?session_id={}&seq={}",
            self.base_url,
            urlencoding::encode(session_id),
            seq
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/x-msgpack")
            .header("Content-Encoding", "zstd")
            .body(chunk_data)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(to_http_error(status, error_text));
        }

        response.json().await.map_err(|e| ApiError::ParseError {
            message: format!("Failed to parse analyze chunk response: {}", e),
        })
    }

    /// Finalize a chunked analysis session.
    ///
    /// Call this after all semantics chunks have been uploaded.
    /// This marks the session as complete and returns final totals.
    pub async fn analyze_finalize(
        &self,
        api_key: &str,
        session_id: &str,
    ) -> Result<AnalyzeFinalizeResponse, ApiError> {
        let url = format!(
            "{}/api/v1/graph/analyze/finalize?session_id={}",
            self.base_url,
            urlencoding::encode(session_id)
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Length", 0)
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(to_http_error(status, error_text));
        }

        response.json().await.map_err(|e| ApiError::ParseError {
            message: format!("Failed to parse analyze finalize response: {}", e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impact_request_serialization_with_session_id() {
        let request = ImpactAnalysisRequest {
            session_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            workspace_id: None,
            file_path: "auth/middleware.py".to_string(),
            max_depth: 5,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(json.contains("auth/middleware.py"));
        assert!(json.contains("\"max_depth\":5"));
        assert!(!json.contains("workspace_id"));
    }

    #[test]
    fn test_impact_request_serialization_with_workspace_id() {
        let request = ImpactAnalysisRequest {
            session_id: None,
            workspace_id: Some("wks_abc123".to_string()),
            file_path: "auth/middleware.py".to_string(),
            max_depth: 5,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wks_abc123"));
        assert!(json.contains("auth/middleware.py"));
        assert!(!json.contains("session_id"));
    }

    #[test]
    fn test_dependency_request_files_using_library() {
        let request = DependencyQueryRequest {
            session_id: None,
            workspace_id: Some("wks_test".to_string()),
            query_type: "files_using_library".to_string(),
            library_name: Some("requests".to_string()),
            file_path: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("files_using_library"));
        assert!(json.contains("requests"));
        assert!(!json.contains("\"file_path\""));
        assert!(json.contains("wks_test"));
    }

    #[test]
    fn test_dependency_request_external_dependencies() {
        let request = DependencyQueryRequest {
            session_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            workspace_id: None,
            query_type: "external_dependencies".to_string(),
            library_name: None,
            file_path: Some("main.py".to_string()),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("external_dependencies"));
        assert!(json.contains("main.py"));
        assert!(!json.contains("library_name"));
        assert!(!json.contains("workspace_id"));
    }

    #[test]
    fn test_centrality_request_serialization_with_workspace_id() {
        let request = CentralityRequest {
            session_id: None,
            workspace_id: Some("wks_test".to_string()),
            limit: 10,
            sort_by: "in_degree".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"limit\":10"));
        assert!(json.contains("in_degree"));
        assert!(json.contains("wks_test"));
        assert!(!json.contains("session_id"));
    }

    #[test]
    fn test_centrality_request_serialization_with_session_id() {
        let request = CentralityRequest {
            session_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            workspace_id: None,
            limit: 10,
            sort_by: "in_degree".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"limit\":10"));
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!json.contains("workspace_id"));
    }

    #[test]
    fn test_impact_response_deserialization() {
        let json = r#"{
            "file_path": "auth/middleware.py",
            "direct_importers": [
                {"path": "api/routes.py", "language": "Python", "depth": 1}
            ],
            "transitive_importers": [
                {"path": "api/routes.py", "language": "Python", "depth": 1},
                {"path": "main.py", "language": "Python", "depth": 2}
            ],
            "total_affected": 2
        }"#;
        let response: ImpactAnalysisResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.file_path, "auth/middleware.py");
        assert_eq!(response.direct_importers.len(), 1);
        assert_eq!(response.transitive_importers.len(), 2);
        assert_eq!(response.total_affected, 2);
    }

    #[test]
    fn test_dependency_response_files() {
        let json = r#"{
            "query_type": "files_using_library",
            "files": [
                {"path": "api/client.py", "language": "Python", "depth": null}
            ],
            "dependencies": null
        }"#;
        let response: DependencyQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.query_type, "files_using_library");
        assert!(response.files.is_some());
        assert!(response.dependencies.is_none());
    }

    #[test]
    fn test_dependency_response_deps() {
        let json = r#"{
            "query_type": "external_dependencies",
            "files": null,
            "dependencies": [
                {"name": "requests", "category": "HttpClient"},
                {"name": "fastapi", "category": "WebFramework"}
            ]
        }"#;
        let response: DependencyQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.query_type, "external_dependencies");
        assert!(response.files.is_none());
        assert!(response.dependencies.is_some());
        assert_eq!(response.dependencies.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_centrality_response_deserialization() {
        let json = r#"{
            "files": [
                {
                    "path": "db/connection.py",
                    "in_degree": 15,
                    "out_degree": 3,
                    "total_degree": 18,
                    "library_usage": 5,
                    "importance_score": 38
                }
            ],
            "total_files": 47,
            "sort_by": "in_degree"
        }"#;
        let response: CentralityResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.files.len(), 1);
        assert_eq!(response.files[0].path, "db/connection.py");
        assert_eq!(response.files[0].in_degree, 15);
        assert_eq!(response.total_files, 47);
        assert_eq!(response.sort_by, "in_degree");
    }

    #[test]
    fn test_graph_stats_response_deserialization() {
        let json = r#"{
            "file_count": 10,
            "function_count": 50,
            "class_count": 5,
            "external_module_count": 8,
            "total_nodes": 73,
            "imports_edge_count": 25,
            "contains_edge_count": 55,
            "uses_library_edge_count": 16,
            "calls_edge_count": 0,
            "total_edges": 96
        }"#;
        let response: GraphStatsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.file_count, 10);
        assert_eq!(response.function_count, 50);
        assert_eq!(response.total_nodes, 73);
        assert_eq!(response.total_edges, 96);
    }

    #[test]
    fn test_compute_ingest_percent_zero_total_is_100() {
        assert_eq!(compute_ingest_percent(0, 0, 0, 0), 100);
    }

    #[test]
    fn test_compute_ingest_percent_progression() {
        assert_eq!(compute_ingest_percent(10, 10, 0, 0), 0);
        assert_eq!(compute_ingest_percent(10, 10, 10, 0), 50);
        assert_eq!(compute_ingest_percent(10, 10, 10, 10), 100);
    }

    // ==================== IR Analysis Types Tests ====================

    #[test]
    fn test_ir_analyze_request_serialization() {
        let request = IrAnalyzeRequest {
            session_id: "00000000-0000-0000-0000-000000000000".to_string(),
            profiles: vec!["stability".to_string(), "security".to_string()],
            semantics_json: "[]".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("00000000-0000-0000-0000-000000000000"));
        assert!(json.contains("stability"));
        assert!(json.contains("security"));
        assert!(json.contains("semantics_json"));
    }

    #[test]
    fn test_ir_analyze_request_without_label() {
        let request = IrAnalyzeRequest {
            session_id: "00000000-0000-0000-0000-000000000001".to_string(),
            profiles: vec!["stability".to_string()],
            semantics_json: "[]".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("00000000-0000-0000-0000-000000000001"));
    }

    #[test]
    fn test_ir_finding_deserialization_full() {
        let json = r#"{
            "rule_id": "missing-circuit-breaker",
            "title": "Missing Circuit Breaker",
            "description": "HTTP calls should use circuit breakers for resilience",
            "severity": "high",
            "dimension": "stability",
            "file_path": "api/client.py",
            "line": 42,
            "column": 5,
            "end_line": 45,
            "end_column": 10,
            "message": "HTTP client calls should use circuit breakers",
            "patch": "--- a/api/client.py\n+++ b/api/client.py",
            "byte_start": 1024,
            "byte_end": 1234
        }"#;
        let finding: IrFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.rule_id, "missing-circuit-breaker");
        assert_eq!(finding.title, "Missing Circuit Breaker");
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.dimension, "stability");
        assert_eq!(finding.file_path, "api/client.py");
        assert_eq!(finding.line, 42);
        assert_eq!(finding.column, 5);
        assert_eq!(finding.end_line, Some(45));
        assert_eq!(finding.end_column, Some(10));
        assert_eq!(
            finding.message,
            "HTTP client calls should use circuit breakers"
        );
        assert!(finding.patch.is_some());
        assert_eq!(finding.byte_start, Some(1024));
        assert_eq!(finding.byte_end, Some(1234));
    }

    #[test]
    fn test_ir_finding_deserialization_minimal() {
        let json = r#"{
            "rule_id": "test-rule",
            "severity": "info",
            "file_path": "test.py",
            "line": 1,
            "column": 1,
            "end_line": 1,
            "end_column": 10,
            "message": "Test message"
        }"#;
        let finding: IrFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.rule_id, "test-rule");
        // dimension defaults to empty string with #[serde(default)]
        assert_eq!(finding.dimension, "");
        assert!(finding.patch.is_none());
        assert!(finding.byte_start.is_none());
    }

    #[test]
    fn test_ir_analyze_response_deserialization() {
        let json = r#"{
            "findings": [
                {
                    "rule_id": "test-rule",
                    "severity": "medium",
                    "file_path": "main.py",
                    "line": 10,
                    "column": 1,
                    "end_line": 10,
                    "end_column": 50,
                    "message": "Consider adding error handling"
                }
            ],
            "file_count": 5,
            "elapsed_ms": 42
        }"#;
        let response: IrAnalyzeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.findings.len(), 1);
        assert_eq!(response.file_count, 5);
        assert_eq!(response.elapsed_ms, 42);
        assert!(response.graph_stats.is_none());
    }

    #[test]
    fn test_ir_analyze_response_with_graph_stats() {
        let json = r#"{
            "findings": [],
            "file_count": 3,
            "elapsed_ms": 15,
            "graph_stats": {
                "file_count": 3,
                "function_count": 10,
                "class_count": 2,
                "external_module_count": 5,
                "import_edge_count": 8,
                "contains_edge_count": 12,
                "uses_library_edge_count": 5,
                "total_nodes": 20,
                "total_edges": 25
            }
        }"#;
        let response: IrAnalyzeResponse = serde_json::from_str(json).unwrap();
        assert!(response.graph_stats.is_some());
        let stats = response.graph_stats.unwrap();
        assert_eq!(stats.file_count, 3);
        assert_eq!(stats.function_count, 10);
        assert_eq!(stats.import_edge_count, 8);
        assert_eq!(stats.contains_edge_count, 12);
    }
}

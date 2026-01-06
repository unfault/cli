//! # Session API
//!
//! This module contains all API endpoints and types related to analysis sessions.

use crate::api::client::{ApiClient, ApiError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Request Types
// =============================================================================

/// Advertised profile from the client
#[derive(Debug, Clone, Serialize)]
pub struct AdvertisedProfile {
    /// Profile identifier (e.g., "python_fastapi_backend")
    pub id: String,
    /// Confidence score [0.0, 1.0]
    pub confidence: f64,
}

/// Meta file from the project
#[derive(Debug, Clone, Serialize)]
pub struct MetaFile {
    /// Path relative to workspace root
    pub path: String,
    /// Language/format (e.g., "toml", "json")
    pub language: String,
    /// Kind of meta file
    pub kind: String,
    /// File contents
    pub contents: String,
}

/// Workspace descriptor for session creation
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceDescriptor {
    /// Stable workspace identifier (computed from git remote or manifest)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Source of the workspace_id (`git`, `manifest`, or `label`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_source: Option<String>,
    /// Human-readable workspace label
    pub label: String,
    /// Git remote URL (normalized form)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_remote: Option<String>,
    /// Profiles the client thinks apply
    pub profiles: Vec<AdvertisedProfile>,
    /// Meta files from the project
    #[serde(default)]
    pub meta_files: Vec<MetaFile>,
}

/// Rule-specific settings for workspace configuration.
///
/// Controls which rules are included/excluded and their severity levels.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiRuleSettings {
    /// Rules to exclude (supports glob patterns like `python.http.*`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,

    /// Additional rules to include beyond the profile defaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// Severity overrides (rule_id → severity).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub severity: HashMap<String, String>,
}

/// Workspace-level configuration for analysis.
///
/// These settings control which profile, rules, and dimensions are used
/// during analysis. Settings are typically read from the project's manifest
/// file (pyproject.toml, Cargo.toml, package.json) or .unfault.toml.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiWorkspaceSettings {
    /// Override the auto-detected profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    /// Limit analysis to specific dimensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<Vec<String>>,

    /// Rule-specific configuration.
    #[serde(default, skip_serializing_if = "ApiRuleSettings::is_empty")]
    pub rules: ApiRuleSettings,
}

impl ApiRuleSettings {
    /// Check if there are no settings configured.
    pub fn is_empty(&self) -> bool {
        self.exclude.is_empty() && self.include.is_empty() && self.severity.is_empty()
    }
}

impl ApiWorkspaceSettings {
    /// Check if there are no settings configured.
    pub fn is_empty(&self) -> bool {
        self.profile.is_none() && self.dimensions.is_none() && self.rules.is_empty()
    }
}

/// Request to create a new session
#[derive(Debug, Clone, Serialize)]
pub struct SessionNewRequest {
    /// Workspace descriptor
    pub workspace: WorkspaceDescriptor,
    /// Optional dimensions to focus on
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_dimensions: Option<Vec<String>>,
    /// Optional workspace settings (profile override, rule exclusions, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_settings: Option<ApiWorkspaceSettings>,
}

/// Source file for analysis
#[derive(Debug, Clone, Serialize)]
pub struct SourceFile {
    /// File path relative to workspace
    pub path: String,
    /// Programming language
    pub language: String,
    /// File contents
    pub contents: String,
}

/// File header for graph building.
///
/// Contains only the import section of a file, used to build a complete
/// dependency graph without sending entire file contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFileHeader {
    /// File path relative to workspace root
    pub path: String,
    /// Programming language (e.g., "python", "rust", "go")
    pub language: String,
    /// Extracted header content (import statements only)
    pub header: String,
}

/// Context containing files to analyze
#[derive(Debug, Clone, Serialize)]
pub struct SessionContextInput {
    /// Context identifier
    pub id: String,
    /// Human-readable label
    pub label: String,
    /// Dimension for this context
    pub dimension: String,
    /// Files to analyze
    pub files: Vec<SourceFile>,
}

/// Project layout information
#[derive(Debug, Clone, Serialize, Default)]
pub struct ProjectLayout {
    /// Source directories
    #[serde(default)]
    pub src_dirs: Vec<String>,
    /// Test directories
    #[serde(default)]
    pub test_dirs: Vec<String>,
    /// Other directories
    #[serde(default)]
    pub other_dirs: Vec<String>,
    /// All directories
    #[serde(default)]
    pub directories: Vec<String>,
}

/// Git information
#[derive(Debug, Clone, Serialize)]
pub struct GitInfo {
    /// Current branch name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Current commit SHA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Remote URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

/// Metadata about the review session
#[derive(Debug, Clone, Serialize)]
pub struct ReviewSessionMeta {
    /// Session label
    pub label: String,
    /// Detected languages
    pub languages: Vec<String>,
    /// Detected frameworks
    #[serde(default)]
    pub framework_guesses: Vec<String>,
    /// Project layout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<ProjectLayout>,
    /// Git information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<GitInfo>,
    /// Requested dimensions
    #[serde(default)]
    pub requested_dimensions: Vec<String>,
}

/// Request to run analysis on a session
#[derive(Debug, Clone, Serialize)]
pub struct SessionRunRequest {
    /// Session metadata
    pub meta: ReviewSessionMeta,
    /// Analysis contexts with files
    pub contexts: Vec<SessionContextInput>,
    /// File headers for complete graph building (optional).
    ///
    /// Contains import sections from ALL source files in the workspace,
    /// not just those matching rule predicates. This enables complete
    /// dependency graph construction for accurate impact analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_headers: Option<Vec<ApiFileHeader>>,
}

// =============================================================================
// Response Types
// =============================================================================

/// File predicate for filtering
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilePredicate {
    /// Type of predicate
    pub kind: String,
    /// Value for language/under_directory predicates
    pub value: Option<String>,
    /// Pattern for path_glob/text_matches_regex predicates
    pub pattern: Option<String>,
    /// Values for text_contains predicates
    pub values: Option<Vec<String>>,
}

/// File query hint for selecting files
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileQueryHint {
    /// Unique hint identifier
    pub id: String,
    /// Human-readable label
    pub label: Option<String>,
    /// Maximum files to select
    pub max_files: Option<i32>,
    /// Maximum total bytes
    pub max_total_bytes: Option<i64>,
    /// Include predicates
    pub include: Vec<FilePredicate>,
    /// Exclude predicates
    #[serde(default)]
    pub exclude: Vec<FilePredicate>,
}

/// Subscription warning for nudging users about trial status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubscriptionWarning {
    /// Type of warning ("trial_ending" or "trial_expired")
    #[serde(rename = "type")]
    pub warning_type: String,
    /// Human-readable warning message
    pub message: String,
    /// Days remaining in trial (None if expired)
    pub days_remaining: Option<i32>,
    /// Current subscription status
    pub subscription_status: String,
    /// URL to upgrade subscription
    pub upgrade_url: String,
}

/// Response from creating a new session
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionNewResponse {
    /// Unique session identifier
    pub session_id: String,
    /// Current session status
    pub status: String,
    /// Workspace label from request
    pub workspace_label: String,
    /// Stable workspace identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Source of the workspace_id (`git`, `manifest`, or `label`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id_source: Option<String>,
    /// Profile IDs that were resolved
    pub selected_profiles: Vec<String>,
    /// File selection hints
    pub file_hints: Vec<FileQueryHint>,
    /// Subscription warning for trial nudges (non-blocking)
    #[serde(default)]
    pub subscription_warning: Option<SubscriptionWarning>,
}

/// Source location for a finding (legacy format)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FindingLocation {
    /// File path relative to workspace root
    pub file: String,
    /// Starting line number (1-indexed)
    pub start_line: u32,
    /// Ending line number (1-indexed, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// Starting column (1-indexed, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    /// Ending column (1-indexed, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

/// Finding from analysis
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Finding {
    /// Unique finding identifier
    pub id: String,
    /// Rule that produced this finding
    pub rule_id: String,
    /// Kind of finding
    pub kind: String,
    /// Short title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: String,
    /// Confidence score
    pub confidence: f64,
    /// Dimension this finding relates to
    pub dimension: String,
    /// File path where this finding was detected (new format)
    #[serde(default)]
    pub file_path: Option<String>,
    /// Line number (1-based) where the finding starts (new format)
    #[serde(default)]
    pub line: Option<u32>,
    /// Column number (1-based) where the finding starts (new format)
    #[serde(default)]
    pub column: Option<u32>,
    /// Line number (1-based) where the finding ends (new format)
    #[serde(default)]
    pub end_line: Option<u32>,
    /// Column number (1-based) where the finding ends (new format)
    #[serde(default)]
    pub end_column: Option<u32>,
    /// Source location (file, line range) - legacy format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<FindingLocation>,
    /// Unified diff for auto-fix
    pub diff: Option<String>,
    /// Preview of the fix
    pub fix_preview: Option<String>,
}

/// Analysis results for a context
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContextResult {
    /// Context identifier
    pub context_id: String,
    /// Context label
    pub label: String,
    /// Findings from analysis
    pub findings: Vec<Finding>,
}

/// Response from running analysis
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionRunResponse {
    /// Session identifier
    pub session_id: String,
    /// Current session status
    pub status: String,
    /// Session metadata
    pub meta: serde_json::Value,
    /// Analysis results per context
    pub contexts: Vec<ContextResult>,
    /// Time taken for analysis in milliseconds (defaults to 0 for backward compatibility)
    #[serde(default)]
    pub elapsed_ms: u64,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Subscription warning for trial nudges (non-blocking)
    #[serde(default)]
    pub subscription_warning: Option<SubscriptionWarning>,
    /// Whether results are limited due to expired trial
    #[serde(default)]
    pub is_limited: bool,
    /// Total findings count (only set when is_limited=true)
    #[serde(default)]
    pub total_findings_count: Option<i32>,
    /// Warning if code graph persistence failed (RAG features won't work)
    #[serde(default)]
    pub graph_warning: Option<String>,
}

/// Response for session status queries
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionStatusResponse {
    /// Session identifier
    pub session_id: String,
    /// Current session status
    pub status: String,
    /// Workspace label
    pub workspace_label: Option<String>,
    /// Stable workspace identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Source of the workspace_id (`git`, `manifest`, or `label`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id_source: Option<String>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// When session was created
    pub created_at: String,
}

/// Response from generating embeddings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionEmbedResponse {
    /// Session identifier
    pub session_id: String,
    /// Number of session-level embeddings created
    pub session_embeddings_created: i32,
    /// Number of finding-level embeddings created
    pub finding_embeddings_created: i32,
    /// Whether embeddings already existed (skipped re-generation)
    pub already_exists: bool,
    /// Time taken for embedding generation in milliseconds
    pub elapsed_ms: u64,
}

/// Health check response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthResponse {
    // Empty response indicates healthy
}

/// Response from session findings endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionFindingsResponse {
    /// Session identifier
    pub session_id: String,
    /// Human-readable workspace label
    pub workspace_label: Option<String>,
    /// Total number of findings
    pub total_count: i32,
    /// Number of Critical severity findings
    pub critical_count: i32,
    /// Number of High severity findings
    pub high_count: i32,
    /// Number of Medium severity findings
    pub medium_count: i32,
    /// Number of Low severity findings
    pub low_count: i32,
    /// Number of Info severity findings
    pub info_count: i32,
    /// Number of findings with auto-fix diffs available
    pub with_diff_count: i32,
    /// All findings from the session
    pub findings: Vec<Finding>,
}

// =============================================================================
// API Client Methods
// =============================================================================

/// Convert a reqwest error to an ApiError.
fn to_network_error(err: reqwest::Error) -> ApiError {
    ApiError::Network {
        message: err.to_string(),
    }
}

/// Convert an HTTP response with error status to an ApiError.
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
        422 => ApiError::ValidationError {
            message: parse_validation_error(&error_text),
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

/// Parse a 422 validation error response and extract a user-friendly message.
///
/// FastAPI/Pydantic returns validation errors in this format:
/// ```json
/// {"detail":[{"type":"value_error","loc":["body","field"],"msg":"Value error, ...","input":...}]}
/// ```
fn parse_validation_error(error_text: &str) -> String {
    // Try to parse as JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(error_text) {
        // Extract detail array
        if let Some(detail) = json.get("detail").and_then(|d| d.as_array()) {
            // Collect all error messages
            let messages: Vec<String> = detail
                .iter()
                .filter_map(|item| {
                    item.get("msg").and_then(|m| m.as_str()).map(|msg| {
                        // Clean up the message - remove "Value error, " prefix if present
                        msg.strip_prefix("Value error, ").unwrap_or(msg).to_string()
                    })
                })
                .collect();

            if !messages.is_empty() {
                return messages.join("; ");
            }
        }
    }

    // Fallback to raw error text if parsing fails
    if error_text.is_empty() {
        "Invalid request data".to_string()
    } else {
        error_text.to_string()
    }
}

impl ApiClient {
    /// Create a new analysis session
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `request` - Session creation request
    ///
    /// # Returns
    ///
    /// * `Ok(SessionNewResponse)` - Session created successfully
    /// * `Err(ApiError)` - Request failed
    pub async fn create_session(
        &self,
        api_key: &str,
        request: &SessionNewRequest,
    ) -> Result<SessionNewResponse, ApiError> {
        let url = format!("{}/api/v1/session/new", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(to_http_error(status, error_text));
        }

        let session_response: SessionNewResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse session response: {}", e),
            })?;

        Ok(session_response)
    }

    /// Run analysis on a session
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `session_id` - Session identifier
    /// * `request` - Analysis run request
    ///
    /// # Returns
    ///
    /// * `Ok(SessionRunResponse)` - Analysis completed
    /// * `Err(ApiError)` - Request failed
    pub async fn run_analysis(
        &self,
        api_key: &str,
        session_id: &str,
        request: &SessionRunRequest,
    ) -> Result<SessionRunResponse, ApiError> {
        let url = format!("{}/api/v1/session/{}/run", self.base_url, session_id);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(request)
            .send()
            .await
            .map_err(to_network_error)?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(to_http_error(status, error_text));
        }

        let run_response: SessionRunResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse analysis response: {}", e),
            })?;

        Ok(run_response)
    }

    /// Get session status
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `session_id` - Session identifier
    ///
    /// # Returns
    ///
    /// * `Ok(SessionStatusResponse)` - Session status retrieved
    /// * `Err(ApiError)` - Request failed
    pub async fn get_session_status(
        &self,
        api_key: &str,
        session_id: &str,
    ) -> Result<SessionStatusResponse, ApiError> {
        let url = format!("{}/api/v1/session/{}", self.base_url, session_id);

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

        let status_response: SessionStatusResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse session status response: {}", e),
            })?;

        Ok(status_response)
    }

    /// Generate embeddings for a completed session
    ///
    /// Embeddings enable RAG features like semantic search and AI insights.
    /// This endpoint is idempotent - calling it multiple times is safe.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `session_id` - Session identifier
    ///
    /// # Returns
    ///
    /// * `Ok(SessionEmbedResponse)` - Embeddings generated (or already existed)
    /// * `Err(ApiError)` - Request failed
    pub async fn generate_embeddings(
        &self,
        api_key: &str,
        session_id: &str,
    ) -> Result<SessionEmbedResponse, ApiError> {
        let url = format!("{}/api/v1/session/{}/embed", self.base_url, session_id);

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

        let embed_response: SessionEmbedResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse embed response: {}", e),
            })?;

        Ok(embed_response)
    }

    /// Check API health
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - API is healthy
    /// * `Ok(false)` - API returned non-success status
    /// * `Err(ApiError)` - Request failed (network error)
    pub async fn health_check(&self) -> Result<bool, ApiError> {
        let url = format!("{}/api/v1/health", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(to_network_error)?;

        Ok(response.status().is_success())
    }

    /// Fetch findings for a completed session.
    ///
    /// This retrieves findings from the `findings` table (chunked analysis path)
    /// or falls back to `result_data` for backward compatibility.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `session_id` - Session identifier
    ///
    /// # Returns
    ///
    /// * `Ok(SessionFindingsResponse)` - Findings retrieved
    /// * `Err(ApiError)` - Request failed
    pub async fn get_session_findings(
        &self,
        api_key: &str,
        session_id: &str,
    ) -> Result<SessionFindingsResponse, ApiError> {
        let url = format!("{}/api/v1/session/{}/findings", self.base_url, session_id);

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
            message: format!("Failed to parse session findings response: {}", e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertised_profile_serialization() {
        let profile = AdvertisedProfile {
            id: "python_fastapi_backend".to_string(),
            confidence: 0.9,
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("python_fastapi_backend"));
        assert!(json.contains("0.9"));
    }

    #[test]
    fn test_workspace_descriptor_serialization() {
        let workspace = WorkspaceDescriptor {
            id: Some("wks_abc123def456".to_string()),
            id_source: Some("git".to_string()),
            label: "my-project".to_string(),
            git_remote: Some("github.com/org/my-project".to_string()),
            profiles: vec![AdvertisedProfile {
                id: "python_fastapi_backend".to_string(),
                confidence: 0.9,
            }],
            meta_files: vec![],
        };
        let json = serde_json::to_string(&workspace).unwrap();
        assert!(json.contains("my-project"));
        assert!(json.contains("python_fastapi_backend"));
        assert!(json.contains("wks_abc123def456"));
        assert!(json.contains("github.com/org/my-project"));
    }

    #[test]
    fn test_session_new_request_serialization() {
        let request = SessionNewRequest {
            workspace: WorkspaceDescriptor {
                id: None,
                id_source: None,
                label: "test-workspace".to_string(),
                git_remote: None,
                profiles: vec![AdvertisedProfile {
                    id: "python_generic_backend".to_string(),
                    confidence: 0.8,
                }],
                meta_files: vec![],
            },
            requested_dimensions: Some(vec!["stability".to_string()]),
            workspace_settings: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-workspace"));
        assert!(json.contains("stability"));
    }

    #[test]
    fn test_session_new_request_with_workspace_settings() {
        let mut severity = std::collections::HashMap::new();
        severity.insert("python.bare_except".to_string(), "low".to_string());

        let request = SessionNewRequest {
            workspace: WorkspaceDescriptor {
                id: None,
                id_source: None,
                label: "test-workspace".to_string(),
                git_remote: None,
                profiles: vec![AdvertisedProfile {
                    id: "python_fastapi_backend".to_string(),
                    confidence: 0.9,
                }],
                meta_files: vec![],
            },
            requested_dimensions: None,
            workspace_settings: Some(ApiWorkspaceSettings {
                profile: Some("python_fastapi_backend".to_string()),
                dimensions: Some(vec!["stability".to_string()]),
                rules: ApiRuleSettings {
                    exclude: vec!["python.http.*".to_string()],
                    include: vec!["python.security.*".to_string()],
                    severity,
                },
            }),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("python_fastapi_backend"));
        assert!(json.contains("workspace_settings"));
        assert!(json.contains("python.http.*"));
        assert!(json.contains("python.security.*"));
        assert!(json.contains("python.bare_except"));
    }

    #[test]
    fn test_session_new_response_deserialization() {
        let json = r#"{
            "session_id": "sess_abc123",
            "status": "created",
            "workspace_label": "my-project",
            "selected_profiles": ["python_fastapi_backend"],
            "file_hints": []
        }"#;
        let response: SessionNewResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.session_id, "sess_abc123");
        assert_eq!(response.status, "created");
        assert_eq!(response.workspace_label, "my-project");
    }

    #[test]
    fn test_finding_deserialization() {
        let json = r#"{
            "id": "finding_001",
            "rule_id": "fastapi.missing_cors",
            "kind": "BehaviorThreat",
            "title": "Missing CORS middleware",
            "description": "FastAPI app has no CORS middleware configured",
            "severity": "Medium",
            "confidence": 0.85,
            "dimension": "Correctness",
            "diff": null,
            "fix_preview": null
        }"#;
        let finding: Finding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.id, "finding_001");
        assert_eq!(finding.rule_id, "fastapi.missing_cors");
        assert_eq!(finding.severity, "Medium");
    }

    #[test]
    fn test_context_result_deserialization() {
        let json = r#"{
            "context_id": "ctx_workspace",
            "label": "Workspace",
            "findings": []
        }"#;
        let result: ContextResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.context_id, "ctx_workspace");
        assert_eq!(result.label, "Workspace");
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_session_status_response_deserialization() {
        let json = r#"{
            "session_id": "sess_xyz789",
            "status": "completed",
            "workspace_label": "test-project",
            "error_message": null,
            "created_at": "2024-01-15T10:30:00Z"
        }"#;
        let response: SessionStatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.session_id, "sess_xyz789");
        assert_eq!(response.status, "completed");
    }

    #[test]
    fn test_source_file_serialization() {
        let file = SourceFile {
            path: "src/main.py".to_string(),
            language: "python".to_string(),
            contents: "print('hello')".to_string(),
        };
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.contains("src/main.py"));
        assert!(json.contains("python"));
    }

    #[test]
    fn test_review_session_meta_serialization() {
        let meta = ReviewSessionMeta {
            label: "test-session".to_string(),
            languages: vec!["python".to_string()],
            framework_guesses: vec!["fastapi".to_string()],
            layout: None,
            git: None,
            requested_dimensions: vec!["stability".to_string()],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("test-session"));
        assert!(json.contains("python"));
        assert!(json.contains("fastapi"));
    }

    #[test]
    fn test_session_run_response_deserialization() {
        let json = r#"{
            "session_id": "sess_abc123",
            "status": "completed",
            "meta": {"label": "test-session", "languages": ["python"]},
            "contexts": [],
            "elapsed_ms": 142,
            "error_message": null
        }"#;
        let response: SessionRunResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.session_id, "sess_abc123");
        assert_eq!(response.status, "completed");
        assert_eq!(response.elapsed_ms, 142);
        assert!(response.error_message.is_none());
    }

    #[test]
    fn test_session_run_response_with_findings() {
        let json = r#"{
            "session_id": "sess_xyz789",
            "status": "completed",
            "meta": {"label": "test-session", "languages": ["python"]},
            "contexts": [
                {
                    "context_id": "ctx_1",
                    "label": "Workspace",
                    "findings": [
                        {
                            "id": "finding_001",
                            "rule_id": "fastapi.missing_cors",
                            "kind": "BehaviorThreat",
                            "title": "Missing CORS",
                            "description": "No CORS configured",
                            "severity": "Medium",
                            "confidence": 0.85,
                            "dimension": "Stability",
                            "diff": null,
                            "fix_preview": null
                        }
                    ]
                }
            ],
            "elapsed_ms": 500,
            "error_message": null
        }"#;
        let response: SessionRunResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.session_id, "sess_xyz789");
        assert_eq!(response.elapsed_ms, 500);
        assert_eq!(response.contexts.len(), 1);
        assert_eq!(response.contexts[0].findings.len(), 1);
    }

    #[test]
    fn test_session_run_response_backward_compatibility() {
        // Test that response without elapsed_ms still deserializes (backward compatibility)
        let json = r#"{
            "session_id": "sess_old123",
            "status": "completed",
            "meta": {"label": "test-session", "languages": ["python"]},
            "contexts": [],
            "error_message": null
        }"#;
        let response: SessionRunResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.session_id, "sess_old123");
        assert_eq!(response.elapsed_ms, 0); // Default value
    }

    #[test]
    fn test_session_embed_response_deserialization() {
        let json = r#"{
            "session_id": "sess_abc123",
            "session_embeddings_created": 1,
            "finding_embeddings_created": 5,
            "already_exists": false,
            "elapsed_ms": 312
        }"#;
        let response: SessionEmbedResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.session_id, "sess_abc123");
        assert_eq!(response.session_embeddings_created, 1);
        assert_eq!(response.finding_embeddings_created, 5);
        assert!(!response.already_exists);
        assert_eq!(response.elapsed_ms, 312);
    }

    #[test]
    fn test_session_embed_response_already_exists() {
        let json = r#"{
            "session_id": "sess_xyz789",
            "session_embeddings_created": 0,
            "finding_embeddings_created": 0,
            "already_exists": true,
            "elapsed_ms": 5
        }"#;
        let response: SessionEmbedResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.session_embeddings_created, 0);
        assert_eq!(response.finding_embeddings_created, 0);
        assert!(response.already_exists);
    }

    #[test]
    fn test_parse_validation_error_fastapi_format() {
        let error_text = r#"{"detail":[{"type":"value_error","loc":["body","meta","requested_dimensions"],"msg":"Value error, Invalid dimension(s): all. Allowed values: correctness, maintainability, observability, performance, reliability, scalability, security, stability","input":["all"],"ctx":{"error":{}}}]}"#;
        let message = parse_validation_error(error_text);
        assert_eq!(
            message,
            "Invalid dimension(s): all. Allowed values: correctness, maintainability, observability, performance, reliability, scalability, security, stability"
        );
    }

    #[test]
    fn test_parse_validation_error_multiple_errors() {
        let error_text = r#"{"detail":[{"msg":"Value error, Invalid field A"},{"msg":"Value error, Invalid field B"}]}"#;
        let message = parse_validation_error(error_text);
        assert_eq!(message, "Invalid field A; Invalid field B");
    }

    #[test]
    fn test_parse_validation_error_no_prefix() {
        let error_text = r#"{"detail":[{"msg":"Something is wrong"}]}"#;
        let message = parse_validation_error(error_text);
        assert_eq!(message, "Something is wrong");
    }

    #[test]
    fn test_parse_validation_error_empty() {
        let message = parse_validation_error("");
        assert_eq!(message, "Invalid request data");
    }

    #[test]
    fn test_parse_validation_error_invalid_json() {
        let message = parse_validation_error("not json at all");
        assert_eq!(message, "not json at all");
    }
}

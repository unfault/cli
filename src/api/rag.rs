//! # RAG API
//!
//! This module contains all API endpoints and types related to RAG (Retrieval-Augmented Generation)
//! for querying project health information.

use crate::api::client::{ApiClient, ApiError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Request Types
// =============================================================================

/// Request to query project health via RAG
///
/// # Example
///
/// ```rust
/// use unfault::api::rag::RAGQueryRequest;
///
/// let request = RAGQueryRequest {
///     query: "How is my service doing?".to_string(),
///     workspace_id: Some("wks_abc123".to_string()),
///     max_sessions: Some(5),
///     max_findings: Some(10),
///     similarity_threshold: Some(0.5),
/// };
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct RAGQueryRequest {
    /// Natural language query about project health.
    pub query: String,
    /// Optional workspace to scope the query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Maximum session contexts to retrieve (1-20).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<i32>,
    /// Maximum finding contexts to retrieve (1-50).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_findings: Option<i32>,
    /// Minimum similarity score for retrieval (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity_threshold: Option<f64>,
}

impl Default for RAGQueryRequest {
    fn default() -> Self {
        Self {
            query: String::new(),
            workspace_id: None,
            max_sessions: Some(5),
            max_findings: Some(10),
            similarity_threshold: Some(0.5),
        }
    }
}

// =============================================================================
// Response Types
// =============================================================================

/// A source document used in RAG response generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RAGSource {
    /// Type of source ('session' or 'finding').
    pub source_type: String,
    /// Source identifier (session_id or finding_id).
    pub id: String,
    /// Cosine similarity score (0-1).
    pub similarity: f64,
    /// Additional source metadata.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Session context retrieved for RAG.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RAGSessionContext {
    /// Session identifier.
    pub session_id: String,
    /// Human-readable workspace name.
    pub workspace_label: Option<String>,
    /// When the session was created.
    pub created_at: Option<String>,
    /// Cosine similarity score.
    pub similarity: f64,
    /// Total findings in this session.
    #[serde(default)]
    pub total_findings: i32,
    /// Findings by dimension.
    #[serde(default)]
    pub dimension_counts: HashMap<String, i32>,
    /// Findings by severity.
    #[serde(default)]
    pub severity_counts: HashMap<String, i32>,
}

/// Finding context retrieved for RAG.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RAGFindingContext {
    /// Finding identifier.
    pub finding_id: String,
    /// Rule that produced this finding.
    pub rule_id: Option<String>,
    /// Finding dimension.
    pub dimension: Option<String>,
    /// Finding severity.
    pub severity: Option<String>,
    /// File where finding was detected.
    pub file_path: Option<String>,
    /// Line number.
    pub line: Option<i32>,
    /// Cosine similarity score.
    pub similarity: f64,
}

/// Response from RAG query.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RAGQueryResponse {
    /// Original query.
    pub query: String,
    /// Retrieved session contexts.
    pub sessions: Vec<RAGSessionContext>,
    /// Retrieved finding contexts.
    pub findings: Vec<RAGFindingContext>,
    /// All sources used for context.
    pub sources: Vec<RAGSource>,
    /// Brief summary of retrieved context for LLM consumption.
    pub context_summary: String,
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
        503 => ApiError::Server {
            status: status_code,
            message: if error_text.is_empty() {
                "Embedding service not available".to_string()
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
    /// Query project health using RAG
    ///
    /// Sends a natural language query to retrieve relevant context about
    /// project health from past analysis sessions and findings.
    ///
    /// # Arguments
    ///
    /// * `api_key` - API key for authentication
    /// * `request` - RAG query request
    ///
    /// # Returns
    ///
    /// * `Ok(RAGQueryResponse)` - Context retrieved successfully
    /// * `Err(ApiError)` - Request failed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use unfault::api::{ApiClient, rag::{RAGQueryRequest, RAGQueryResponse}};
    ///
    /// async fn query_health() -> Result<RAGQueryResponse, unfault::api::ApiError> {
    ///     let client = ApiClient::new("https://app.unfault.dev".to_string());
    ///     let request = RAGQueryRequest {
    ///         query: "How is my service doing?".to_string(),
    ///         ..Default::default()
    ///     };
    ///     client.query_rag("sk_live_...", &request).await
    /// }
    /// ```
    pub async fn query_rag(
        &self,
        api_key: &str,
        request: &RAGQueryRequest,
    ) -> Result<RAGQueryResponse, ApiError> {
        let url = format!("{}/api/v1/rag/query", self.base_url);

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

        let rag_response: RAGQueryResponse =
            response.json().await.map_err(|e| ApiError::ParseError {
                message: format!("Failed to parse RAG response: {}", e),
            })?;

        Ok(rag_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rag_query_request_serialization() {
        let request = RAGQueryRequest {
            query: "How is my service doing?".to_string(),
            workspace_id: Some("wks_abc123".to_string()),
            max_sessions: Some(5),
            max_findings: Some(10),
            similarity_threshold: Some(0.5),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("How is my service doing?"));
        assert!(json.contains("wks_abc123"));
        assert!(json.contains("\"max_sessions\":5"));
    }

    #[test]
    fn test_rag_query_request_minimal_serialization() {
        let request = RAGQueryRequest {
            query: "Test query".to_string(),
            workspace_id: None,
            max_sessions: None,
            max_findings: None,
            similarity_threshold: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test query"));
        assert!(!json.contains("workspace_id"));
        assert!(!json.contains("max_sessions"));
    }

    #[test]
    fn test_rag_query_request_default() {
        let request = RAGQueryRequest::default();
        assert!(request.query.is_empty());
        assert!(request.workspace_id.is_none());
        assert_eq!(request.max_sessions, Some(5));
        assert_eq!(request.max_findings, Some(10));
        assert_eq!(request.similarity_threshold, Some(0.5));
    }

    #[test]
    fn test_rag_source_deserialization() {
        let json = r#"{
            "source_type": "session",
            "id": "sess_abc123",
            "similarity": 0.85,
            "metadata": {"total_findings": 5}
        }"#;
        let source: RAGSource = serde_json::from_str(json).unwrap();
        assert_eq!(source.source_type, "session");
        assert_eq!(source.id, "sess_abc123");
        assert!((source.similarity - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_rag_session_context_deserialization() {
        let json = r#"{
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "workspace_label": "payments-service",
            "similarity": 0.85,
            "total_findings": 5,
            "dimension_counts": {"Stability": 2, "Performance": 3},
            "severity_counts": {"High": 1, "Medium": 4}
        }"#;
        let context: RAGSessionContext = serde_json::from_str(json).unwrap();
        assert_eq!(context.session_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            context.workspace_label,
            Some("payments-service".to_string())
        );
        assert_eq!(context.total_findings, 5);
        assert_eq!(context.dimension_counts.get("Stability"), Some(&2));
    }

    #[test]
    fn test_rag_finding_context_deserialization() {
        let json = r#"{
            "finding_id": "http.timeout:api/client.py:42",
            "rule_id": "http.timeout",
            "dimension": "Stability",
            "severity": "High",
            "file_path": "api/client.py",
            "line": 42,
            "similarity": 0.78
        }"#;
        let context: RAGFindingContext = serde_json::from_str(json).unwrap();
        assert_eq!(context.finding_id, "http.timeout:api/client.py:42");
        assert_eq!(context.rule_id, Some("http.timeout".to_string()));
        assert_eq!(context.line, Some(42));
    }

    #[test]
    fn test_rag_query_response_deserialization() {
        let json = r#"{
            "query": "How is my service doing?",
            "sessions": [],
            "findings": [],
            "sources": [],
            "context_summary": "No relevant context found."
        }"#;
        let response: RAGQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.query, "How is my service doing?");
        assert!(response.sessions.is_empty());
        assert!(response.findings.is_empty());
        assert_eq!(response.context_summary, "No relevant context found.");
    }

    #[test]
    fn test_rag_query_response_full_deserialization() {
        let json = r#"{
            "query": "How is my payments service doing?",
            "sessions": [
                {
                    "session_id": "550e8400-e29b-41d4-a716-446655440000",
                    "workspace_label": "payments-service",
                    "similarity": 0.85,
                    "total_findings": 5,
                    "dimension_counts": {"Stability": 2, "Performance": 3},
                    "severity_counts": {"High": 1, "Medium": 4}
                }
            ],
            "findings": [
                {
                    "finding_id": "http.timeout:api/client.py:42",
                    "rule_id": "http.timeout",
                    "dimension": "Stability",
                    "severity": "High",
                    "file_path": "api/client.py",
                    "line": 42,
                    "similarity": 0.78
                }
            ],
            "sources": [
                {
                    "source_type": "session",
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "similarity": 0.85,
                    "metadata": {"total_findings": 5}
                }
            ],
            "context_summary": "Retrieved 1 session for payments-service with 5 findings."
        }"#;
        let response: RAGQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.sessions.len(), 1);
        assert_eq!(response.findings.len(), 1);
        assert_eq!(response.sources.len(), 1);
    }
}

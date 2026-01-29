//! # API Client Core
//!
//! This module contains the main ApiClient structure and HTTP client functionality
//! that is shared across all API operations.

use reqwest::Client;
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use thiserror::Error;
use uuid::Uuid;

/// Error types for API operations.
///
/// This enum distinguishes between different error conditions that can occur
/// during API calls, allowing callers to handle them appropriately.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Authentication error (401 Unauthorized)
    ///
    /// The API key is invalid, expired, or not provided.
    /// User should run `unfault login` to re-authenticate.
    #[error("Authentication failed: {message}")]
    Unauthorized {
        /// Human-readable error message
        message: String,
    },

    /// Authorization error (403 Forbidden)
    ///
    /// The API key is valid but doesn't have permission for this operation.
    #[error("Access denied: {message}")]
    Forbidden {
        /// Human-readable error message
        message: String,
    },

    /// Network error (connection failed, DNS error, timeout, etc.)
    ///
    /// Could not connect to the API server.
    #[error("Network error: {message}")]
    Network {
        /// Human-readable error message
        message: String,
    },

    /// Server error (5xx status codes)
    ///
    /// The API server encountered an error.
    #[error("Server error: {message}")]
    Server {
        /// HTTP status code
        status: u16,
        /// Human-readable error message
        message: String,
    },

    /// Client error (4xx status codes other than 401/402/403/422)
    ///
    /// The request was malformed or invalid.
    #[error("Request error: {message}")]
    ClientError {
        /// HTTP status code
        status: u16,
        /// Human-readable error message
        message: String,
    },

    /// Validation error (422 Unprocessable Entity)
    ///
    /// The request data failed validation (e.g., invalid dimension names).
    #[error("Validation error: {message}")]
    ValidationError {
        /// Human-readable error message
        message: String,
    },

    /// Response parsing error
    ///
    /// The response from the server could not be parsed.
    #[error("Failed to parse response: {message}")]
    ParseError {
        /// Human-readable error message
        message: String,
    },
}

impl ApiError {
    /// Check if this is an authentication error (401 or 403).
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            ApiError::Unauthorized { .. } | ApiError::Forbidden { .. }
        )
    }

    /// Check if this is a network error.
    pub fn is_network_error(&self) -> bool {
        matches!(self, ApiError::Network { .. })
    }

    /// Check if this is a server error.
    pub fn is_server_error(&self) -> bool {
        matches!(self, ApiError::Server { .. })
    }
}

/// HTTP client for interacting with the Unfault API
///
/// The client handles all API communication including authentication,
/// service management, code analysis, and resource management.
///
/// # Example
///
/// ```rust,no_run
/// use unfault::api::ApiClient;
///
/// let client = ApiClient::new("https://app.unfault.dev".to_string());
/// ```
pub struct ApiClient {
    /// Base URL for the API (e.g., <https://app.unfault.dev>)
    pub base_url: String,
    /// Underlying HTTP client
    pub client: Client,
    /// Trace ID for distributed tracing (GCP Cloud Trace format)
    pub trace_id: String,
}

/// Version of the CLI, used in User-Agent header
const VERSION: &str = env!("CARGO_PKG_VERSION");

impl ApiClient {
    /// Create a new API client with proper headers for WAF compatibility
    ///
    /// The client is configured with:
    /// - User-Agent: `unfault/<version>` to identify the CLI
    /// - Accept: `application/json` for API responses
    /// - Content-Type: `application/json` for request bodies
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL for the API endpoint
    ///
    /// # Example
    ///
    /// ```rust
    /// use unfault::api::ApiClient;
    ///
    /// let client = ApiClient::new("https://app.unfault.dev".to_string());
    /// ```
    pub fn new(base_url: String) -> Self {
        // Generate a unique trace ID for this CLI session (128-bit hex)
        let trace_id = generate_trace_id();

        let mut headers = HeaderMap::new();

        // User-Agent header to identify the CLI to the server and WAF
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&format!("unfault/{VERSION}"))
                .unwrap_or_else(|_| HeaderValue::from_static("unfault/0.1.0")),
        );

        // Accept header for JSON responses
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        // Prefer uncompressed responses.
        // Some proxy/tunnel setups have been observed to send incorrect Content-Encoding,
        // which triggers reqwest "error decoding response body".
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));

        // Content-Type header for JSON request bodies
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // X-Cloud-Trace-Context header for distributed tracing (GCP format)
        // Format: TRACE_ID/SPAN_ID;o=TRACE_TRUE
        // - TRACE_ID: 32-character hex (128-bit)
        // - SPAN_ID: 16-character hex (64-bit) - we use 1 for root span
        // - o=1: trace is sampled
        let trace_header = format!("{}/1;o=1", trace_id);
        if let Ok(header_value) = HeaderValue::from_str(&trace_header) {
            headers.insert("X-Cloud-Trace-Context", header_value);
        }

        let client = Client::builder()
            // Disable automatic decompression to avoid failing on mismatched
            // Content-Encoding headers from intermediaries.
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .default_headers(headers)
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            base_url,
            client,
            trace_id,
        }
    }

    /// Get the trace ID for this client session.
    ///
    /// This can be used to correlate CLI operations with API traces in Cloud Trace.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }
}

/// Generate a 128-bit trace ID as a 32-character hex string.
///
/// This follows the GCP Cloud Trace format for trace IDs.
/// Uses UUID v4 (random) and converts to hex without hyphens.
fn generate_trace_id() -> String {
    Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_new() {
        let client = ApiClient::new("https://api.example.com".to_string());
        assert_eq!(client.base_url, "https://api.example.com");
    }

    #[test]
    fn test_trace_id_generation() {
        let trace_id = generate_trace_id();
        assert_eq!(trace_id.len(), 32);
        // Verify it's valid hex
        assert!(trace_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_api_client_has_trace_id() {
        let client = ApiClient::new("https://api.example.com".to_string());
        assert_eq!(client.trace_id().len(), 32);
    }
}

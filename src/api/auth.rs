//! # Authentication API
//!
//! This module contains all API endpoints and types related to authentication operations.

use crate::api::client::ApiClient;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Request body for polling device authentication status
#[derive(Debug, Serialize)]
struct DeviceCodePollRequest {
    /// The device code returned from the initial device flow request
    device_code: String,
}

/// Response from initiating device flow authentication
#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    /// The user code to display to the user
    user_code: String,
    /// The device code for polling authentication status
    device_code: String,
    /// The URL where users should enter their user code
    verification_uri: String,
    /// Time in seconds until the codes expire
    #[allow(dead_code)]
    expires_in: i32,
}

/// Response from polling device authentication
///
/// This is a tagged enum that represents the different states
/// of the authentication process.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status")]
enum PollResponse {
    /// Authentication is pending - keep polling
    #[serde(rename = "pending")]
    Pending,
    /// Authentication is complete - contains the API key
    #[serde(rename = "complete")]
    Complete {
        /// The API key to use for subsequent requests
        api_key: String,
    },
    /// Authentication has expired - user must restart the flow
    #[serde(rename = "expired")]
    Expired,
}

impl ApiClient {
    /// Initiate device flow authentication
    ///
    /// Returns a tuple of (device_code, user_code, verification_uri).
    /// The user should visit the verification URI and enter the user code.
    ///
    /// # Returns
    ///
    /// * `Ok((device_code, user_code, verification_uri))` - Authentication codes
    /// * `Err(_)` - If the request fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use unfault::api::ApiClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = ApiClient::new("https://app.unfault.dev".to_string());
    /// let (device_code, user_code, uri) = client.start_device_flow().await?;
    /// println!("Visit {} and enter code: {}", uri, user_code);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start_device_flow(&self) -> Result<(String, String, String)> {
        let url = format!("{}/api/v1/auth/device/code", self.base_url);

        // Send empty JSON body to ensure Content-Length header is set
        // WAF may reject POST requests without Content-Length (HTTP 411)
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("Failed to start device flow")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to start device flow: HTTP {}", response.status());
        }

        let device_response: DeviceCodeResponse = response
            .json()
            .await
            .context("Failed to parse device code response")?;

        Ok((
            device_response.device_code,
            device_response.user_code,
            device_response.verification_uri,
        ))
    }

    /// Poll for device authentication completion
    ///
    /// # Arguments
    ///
    /// * `device_code` - The device code from [`start_device_flow`](ApiClient::start_device_flow)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(api_key))` - Authentication complete, returns API key
    /// * `Ok(None)` - Still pending, continue polling
    /// * `Err(_)` - Authentication expired or failed
    pub async fn poll_device_auth(&self, device_code: &str) -> Result<Option<String>> {
        let url = format!("{}/api/v1/auth/device/poll", self.base_url);

        let request = DeviceCodePollRequest {
            device_code: device_code.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to poll device authentication")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to poll device authentication: HTTP {}",
                response.status()
            );
        }

        let poll_response: PollResponse = response
            .json()
            .await
            .context("Failed to parse poll response")?;

        match poll_response {
            PollResponse::Complete { api_key } => Ok(Some(api_key)),
            PollResponse::Pending => Ok(None),
            PollResponse::Expired => anyhow::bail!("Authentication expired. Please try again."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_code_poll_request_serialization() {
        let request = DeviceCodePollRequest {
            device_code: "test-device-123".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-device-123"));
        assert!(json.contains("device_code"));
    }

    #[test]
    fn test_poll_response_complete_deserialization() {
        let json = r#"{"status":"complete","api_key":"uf_live_test123"}"#;
        let response: PollResponse = serde_json::from_str(json).unwrap();

        match response {
            PollResponse::Complete { api_key } => {
                assert_eq!(api_key, "uf_live_test123");
            }
            _ => panic!("Expected Complete variant"),
        }
    }

    #[test]
    fn test_poll_response_pending_deserialization() {
        let json = r#"{"status":"pending"}"#;
        let response: PollResponse = serde_json::from_str(json).unwrap();

        match response {
            PollResponse::Pending => {}
            _ => panic!("Expected Pending variant"),
        }
    }

    #[test]
    fn test_poll_response_expired_deserialization() {
        let json = r#"{"status":"expired"}"#;
        let response: PollResponse = serde_json::from_str(json).unwrap();

        match response {
            PollResponse::Expired => {}
            _ => panic!("Expected Expired variant"),
        }
    }

    #[test]
    fn test_device_code_response_deserialization() {
        let json = r#"{
            "device_code": "abc123",
            "user_code": "ABCD1234",
            "verification_uri": "https://unfault.dev/auth/device",
            "expires_in": 600
        }"#;
        let response: DeviceCodeResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.device_code, "abc123");
        assert_eq!(response.user_code, "ABCD1234");
        assert_eq!(response.verification_uri, "https://unfault.dev/auth/device");
        assert_eq!(response.expires_in, 600);
    }

    #[test]
    fn test_device_code_response_complete_deserialization() {
        let json = r#"{
            "device_code": "xyz789",
            "user_code": "EFGH5678",
            "verification_uri": "https://app.unfault.dev/device",
            "expires_in": 900
        }"#;
        
        let response: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.device_code, "xyz789");
        assert_eq!(response.user_code, "EFGH5678");
        assert_eq!(response.verification_uri, "https://app.unfault.dev/device");
        assert_eq!(response.expires_in, 900);
    }

    #[test]
    fn test_poll_response_complete_with_different_api_key() {
        let json = r#"{"status":"complete","api_key":"uf_live_12345678901234567890123456789012"}"#;
        let response: PollResponse = serde_json::from_str(json).unwrap();

        match response {
            PollResponse::Complete { api_key } => {
                assert_eq!(api_key.len(), 40);
                assert!(api_key.starts_with("uf_live_"));
            }
            _ => panic!("Expected Complete variant"),
        }
    }

    #[test]
    fn test_poll_response_serialization_roundtrip() {
        let original = PollResponse::Complete {
            api_key: "uf_live_test_key_12345".to_string(),
        };
        
        let json = serde_json::to_string(&original).unwrap();
        let parsed: PollResponse = serde_json::from_str(&json).unwrap();
        
        match parsed {
            PollResponse::Complete { api_key } => {
                assert_eq!(api_key, "uf_live_test_key_12345");
            }
            _ => panic!("Expected Complete variant"),
        }
    }

    #[test]
    fn test_device_code_poll_request_with_empty_device_code() {
        let request = DeviceCodePollRequest {
            device_code: "".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"device_code\":\"\""));
    }

    #[test]
    fn test_device_code_poll_request_with_special_characters() {
        let request = DeviceCodePollRequest {
            device_code: "test-device_123@456.com".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-device_123@456.com"));
    }

    #[test]
    fn test_poll_response_pending_variant() {
        let response = PollResponse::Pending;
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"status":"pending"}"#);
    }

    #[test]
    fn test_poll_response_expired_variant() {
        let response = PollResponse::Expired;
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"status":"expired"}"#);
    }

    #[test]
    fn test_device_code_response_with_long_expires_in() {
        let json = r#"{
            "device_code": "long_expire_device_123",
            "user_code": "XYZW1234",
            "verification_uri": "https://unfault.dev/auth",
            "expires_in": 3600
        }"#;
        
        let response: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.expires_in, 3600);
    }

    #[test]
    fn test_device_code_response_with_minimal_expires_in() {
        let json = r#"{
            "device_code": "short_expire_456",
            "user_code": "MINI123",
            "verification_uri": "https://example.com/auth",
            "expires_in": 60
        }"#;
        
        let response: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.expires_in, 60);
    }

    #[test]
    fn test_multiple_api_key_formats() {
        let test_cases = vec![
            "uf_live_12345678901234567890123456789012", // 40 chars
            "uf_live_abcdefghijklmnopqrstuvwxyz123456", // 40 chars
            "uf_live_98765432109876543210987654321098", // 40 chars
        ];
        
        for key in test_cases {
            let json = format!(r#"{{"status":"complete","api_key":"{}"}}"#, key);
            let response: PollResponse = serde_json::from_str(&json).unwrap();
            
            match response {
                PollResponse::Complete { api_key } => {
                    assert_eq!(api_key, key);
                    assert_eq!(api_key.len(), 40);
                }
                _ => panic!("Expected Complete variant"),
            }
        }
    }

    #[test]
    fn test_device_code_with_unicode_characters() {
        let json = r#"{
            "device_code": "unicode-测试-тест-🔐",
            "user_code": "UNICODE",
            "verification_uri": "https://测试.com/auth",
            "expires_in": 300
        }"#;
        
        let response: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert!(response.device_code.contains("测试"));
        assert!(response.verification_uri.contains("测试"));
    }
}
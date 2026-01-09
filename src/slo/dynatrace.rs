//! Dynatrace SLO provider implementation.
//!
//! Fetches SLOs from the Dynatrace API using API token authentication.
//!
//! ## Credential Detection
//!
//! Credentials are detected from:
//! 1. `DT_API_TOKEN` environment variable (the API token with `slo.read` scope)
//! 2. `DT_ENVIRONMENT_URL` environment variable (e.g., `https://abc12345.live.dynatrace.com`)
//!
//! ## API Reference
//!
//! - List SLOs: `GET https://{environment-id}.live.dynatrace.com/api/v2/slo`

use std::env;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use super::types::{SloDefinition, SloProviderKind};

/// Dynatrace SLO provider.
pub struct DynatraceProvider {
    api_token: String,
    environment_url: String,
}

impl DynatraceProvider {
    /// Check if Dynatrace credentials are available.
    pub fn is_available() -> bool {
        env::var("DT_API_TOKEN").is_ok() && env::var("DT_ENVIRONMENT_URL").is_ok()
    }

    /// Create a new Dynatrace provider from environment variables.
    ///
    /// Returns `None` if credentials are not available.
    pub fn from_env() -> Option<Self> {
        let api_token = env::var("DT_API_TOKEN").ok()?;
        let environment_url = env::var("DT_ENVIRONMENT_URL").ok()?;

        // Normalize the URL (remove trailing slash)
        let environment_url = environment_url.trim_end_matches('/').to_string();

        Some(Self {
            api_token,
            environment_url,
        })
    }

    /// Fetch all SLOs from Dynatrace.
    pub async fn fetch_slos(&self, client: &Client) -> Result<Vec<SloDefinition>> {
        let mut all_slos = Vec::new();
        let mut next_page_key: Option<String> = None;

        loop {
            let mut url = format!("{}/api/v2/slo?pageSize=100&evaluate=true", self.environment_url);
            if let Some(ref key) = next_page_key {
                url = format!("{}/api/v2/slo?nextPageKey={}", self.environment_url, key);
            }

            let resp = client
                .get(&url)
                .header("Authorization", format!("Api-Token {}", self.api_token))
                .header("Accept", "application/json")
                .send()
                .await
                .context("Failed to send request to Dynatrace API")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Dynatrace API error: {} - {}", status, body);
            }

            let response: DynatraceSloResponse = resp
                .json()
                .await
                .context("Failed to parse Dynatrace SLO response")?;

            all_slos.extend(
                response
                    .slo
                    .into_iter()
                    .map(|slo| self.convert_slo(slo)),
            );

            // Check for more pages
            if let Some(key) = response.next_page_key {
                next_page_key = Some(key);
            } else {
                break;
            }
        }

        Ok(all_slos)
    }

    fn convert_slo(&self, slo: DynatraceSlo) -> SloDefinition {
        // Extract path pattern from filter or name
        // Dynatrace uses entity selectors; we look for URL patterns in the name/description
        let path_pattern = extract_path_from_name(&slo.name)
            .or_else(|| slo.description.as_ref().and_then(|d| extract_path_from_name(d)));

        // Dynatrace SLOs don't typically specify HTTP method
        let http_method = None;

        // Determine timeframe from the SLO's configured timeframe
        let timeframe = slo
            .timeframe
            .as_ref()
            .map(|t| t.to_lowercase())
            .unwrap_or_else(|| "30d".to_string());

        // Build dashboard URL
        let dashboard_url = Some(format!(
            "{}/ui/settings/builtin:monitoring.slo/{}",
            self.environment_url, slo.id
        ));

        SloDefinition {
            id: slo.id.clone(),
            name: slo.name,
            provider: SloProviderKind::Dynatrace,
            path_pattern,
            http_method,
            target_percent: slo.target,
            current_percent: slo.evaluated_percentage,
            error_budget_remaining: slo.error_budget,
            timeframe,
            dashboard_url,
        }
    }
}

/// Try to extract a URL path pattern from an SLO name or description.
///
/// Looks for patterns like:
/// - "API /users availability"
/// - "Service: /api/v1/users"
/// - "Latency for GET /orders"
fn extract_path_from_name(text: &str) -> Option<String> {
    // Look for URL-like patterns starting with /
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '*');
        if clean.starts_with('/') && clean.len() > 1 {
            return Some(clean.to_string());
        }
    }
    None
}

// Dynatrace API response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynatraceSloResponse {
    slo: Vec<DynatraceSlo>,
    next_page_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynatraceSlo {
    id: String,
    name: String,
    description: Option<String>,
    target: f64,
    timeframe: Option<String>,
    evaluated_percentage: Option<f64>,
    error_budget: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_path_from_name() {
        assert_eq!(
            extract_path_from_name("API /users availability"),
            Some("/users".to_string())
        );
        assert_eq!(
            extract_path_from_name("Service: /api/v1/users latency"),
            Some("/api/v1/users".to_string())
        );
        assert_eq!(
            extract_path_from_name("GET /orders success rate"),
            Some("/orders".to_string())
        );
        assert_eq!(extract_path_from_name("General availability SLO"), None);
    }

    #[test]
    fn test_is_available_checks_both_vars() {
        // This test verifies the logic without modifying env vars
        // (which is unsafe in Rust 2024 edition)
        // The function requires BOTH DT_API_TOKEN and DT_ENVIRONMENT_URL to be set
        let has_token = env::var("DT_API_TOKEN").is_ok();
        let has_url = env::var("DT_ENVIRONMENT_URL").is_ok();
        let expected = has_token && has_url;
        assert_eq!(DynatraceProvider::is_available(), expected);
    }
}

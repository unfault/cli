//! Datadog SLO provider implementation.
//!
//! Fetches SLOs from the Datadog API using API key authentication.
//!
//! ## Credential Detection
//!
//! Credentials are detected from:
//! 1. `DD_API_KEY` and `DD_APP_KEY` environment variables
//!
//! ## API Reference
//!
//! - List SLOs: `GET https://api.datadoghq.com/api/v1/slo`

use std::env;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use super::types::{SloDefinition, SloProviderKind};

/// Datadog SLO provider.
pub struct DatadogProvider {
    api_key: String,
    app_key: String,
    site: String,
}

impl DatadogProvider {
    /// Check if Datadog credentials are available.
    pub fn is_available() -> bool {
        env::var("DD_API_KEY").is_ok() && env::var("DD_APP_KEY").is_ok()
    }

    /// Create a new Datadog provider from environment variables.
    ///
    /// Returns `None` if credentials are not available.
    pub fn from_env() -> Option<Self> {
        let api_key = env::var("DD_API_KEY").ok()?;
        let app_key = env::var("DD_APP_KEY").ok()?;

        // Site can be customized for EU/other regions
        let site = env::var("DD_SITE").unwrap_or_else(|_| "datadoghq.com".to_string());

        Some(Self {
            api_key,
            app_key,
            site,
        })
    }

    /// Fetch all SLOs from Datadog.
    pub async fn fetch_slos(&self, client: &Client) -> Result<Vec<SloDefinition>> {
        let url = format!("https://api.{}/api/v1/slo", self.site);

        let resp = client
            .get(&url)
            .header("DD-API-KEY", &self.api_key)
            .header("DD-APPLICATION-KEY", &self.app_key)
            .header("Accept", "application/json")
            .send()
            .await
            .context("Failed to send request to Datadog API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Datadog API error: {} - {}", status, body);
        }

        let response: DatadogSloListResponse = resp
            .json()
            .await
            .context("Failed to parse Datadog SLO response")?;

        Ok(response
            .data
            .into_iter()
            .map(|slo| self.convert_slo(slo))
            .collect())
    }

    fn convert_slo(&self, slo: DatadogSlo) -> SloDefinition {
        // Extract path pattern from tags (common convention: "path:/api/users/*")
        let path_pattern = slo.tags.iter().find_map(|tag| {
            tag.strip_prefix("path:")
                .or_else(|| tag.strip_prefix("endpoint:"))
                .map(|path| path.to_string())
        });

        // Extract HTTP method from tags if present
        let http_method = slo.tags.iter().find_map(|tag| {
            tag.strip_prefix("method:")
                .map(|method| method.to_uppercase())
        });

        // Get the primary threshold (typically 30d)
        let primary_threshold = slo
            .thresholds
            .iter()
            .find(|t| t.timeframe == "30d")
            .or(slo.thresholds.first());

        let (target_percent, timeframe) = primary_threshold
            .map(|t| (t.target, t.timeframe.clone()))
            .unwrap_or((99.0, "30d".to_string()));

        // Build dashboard URL
        let dashboard_url = Some(format!("https://app.{}/slo?slo_id={}", self.site, slo.id));

        let current_percent = slo.overall_status.as_ref().map(|s| s.sli_value);
        let error_budget_remaining = slo
            .overall_status
            .as_ref()
            .and_then(|s| s.error_budget_remaining);

        SloDefinition {
            id: slo.id,
            name: slo.name,
            provider: SloProviderKind::Datadog,
            path_pattern,
            http_method,
            target_percent,
            current_percent,
            error_budget_remaining,
            timeframe,
            dashboard_url,
        }
    }
}

// Datadog API response types

#[derive(Debug, Deserialize)]
struct DatadogSloListResponse {
    data: Vec<DatadogSlo>,
}

#[derive(Debug, Deserialize)]
struct DatadogSlo {
    id: String,
    name: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    thresholds: Vec<DatadogThreshold>,
    overall_status: Option<DatadogOverallStatus>,
}

#[derive(Debug, Deserialize)]
struct DatadogThreshold {
    target: f64,
    timeframe: String,
}

#[derive(Debug, Deserialize)]
struct DatadogOverallStatus {
    sli_value: f64,
    error_budget_remaining: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available_checks_both_keys() {
        // This test verifies the logic without modifying env vars
        // (which is unsafe in Rust 2024 edition)
        // The function requires BOTH DD_API_KEY and DD_APP_KEY to be set
        let has_api_key = env::var("DD_API_KEY").is_ok();
        let has_app_key = env::var("DD_APP_KEY").is_ok();
        let expected = has_api_key && has_app_key;
        assert_eq!(DatadogProvider::is_available(), expected);
    }
}

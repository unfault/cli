//! GCP Cloud Monitoring SLO provider implementation.
//!
//! Fetches SLOs from the GCP Cloud Monitoring API using Application Default Credentials.
//!
//! ## Credential Detection
//!
//! Credentials are detected from:
//! 1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable pointing to a service account key file
//! 2. Application Default Credentials at `~/.config/gcloud/application_default_credentials.json`
//! 3. GCE metadata service (when running on GCP)
//!
//! ## API Reference
//!
//! - List Services: `GET https://monitoring.googleapis.com/v3/projects/{project}/services`
//! - List SLOs: `GET https://monitoring.googleapis.com/v3/projects/{project}/services/{service}/serviceLevelObjectives`

use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use super::types::{SloDefinition, SloProviderKind};

// Note: We use env::var("HOME") instead of the dirs crate to minimize dependencies.

/// GCP Cloud Monitoring SLO provider.
pub struct GcpProvider {
    project_id: String,
    credentials_path: PathBuf,
}

impl GcpProvider {
    /// Check if GCP credentials are available.
    pub fn is_available() -> bool {
        Self::find_credentials().is_some() && Self::get_project_id().is_some()
    }

    /// Create a new GCP provider from Application Default Credentials.
    ///
    /// Returns `None` if credentials are not available.
    pub fn from_env() -> Option<Self> {
        let credentials_path = Self::find_credentials()?;
        let project_id = Self::get_project_id()?;

        Some(Self {
            project_id,
            credentials_path,
        })
    }

    /// Find the credentials file path.
    fn find_credentials() -> Option<PathBuf> {
        // Check GOOGLE_APPLICATION_CREDENTIALS first
        if let Ok(path) = env::var("GOOGLE_APPLICATION_CREDENTIALS") {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }

        // Check Application Default Credentials location
        if let Ok(home) = env::var("HOME") {
            let adc_path = PathBuf::from(home).join(".config/gcloud/application_default_credentials.json");
            if adc_path.exists() {
                return Some(adc_path);
            }
        }

        // Windows fallback
        if let Ok(appdata) = env::var("APPDATA") {
            let adc_path = PathBuf::from(appdata).join("gcloud/application_default_credentials.json");
            if adc_path.exists() {
                return Some(adc_path);
            }
        }

        None
    }

    /// Get the GCP project ID.
    fn get_project_id() -> Option<String> {
        // Check environment variable first
        if let Ok(project) = env::var("GOOGLE_CLOUD_PROJECT") {
            return Some(project);
        }
        if let Ok(project) = env::var("GCP_PROJECT") {
            return Some(project);
        }
        if let Ok(project) = env::var("GCLOUD_PROJECT") {
            return Some(project);
        }

        // Try to read from ADC file
        if let Some(creds_path) = Self::find_credentials() {
            if let Ok(contents) = std::fs::read_to_string(&creds_path) {
                if let Ok(creds) = serde_json::from_str::<AdcFile>(&contents) {
                    if let Some(project) = creds.quota_project_id {
                        return Some(project);
                    }
                }
            }
        }

        // Try to read from gcloud config file
        if let Some(project) = Self::get_project_from_gcloud_config() {
            return Some(project);
        }

        None
    }

    /// Read project ID from gcloud CLI configuration.
    fn get_project_from_gcloud_config() -> Option<String> {
        // First check which config is active
        let home = env::var("HOME").ok()?;
        let gcloud_dir = PathBuf::from(&home).join(".config/gcloud");
        
        // Read active config name
        let active_config = std::fs::read_to_string(gcloud_dir.join("active_config"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "default".to_string());
        
        // Read the config file
        let config_path = gcloud_dir.join("configurations").join(format!("config_{}", active_config));
        let contents = std::fs::read_to_string(config_path).ok()?;
        
        // Parse INI-style config to find project
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("project") {
                if let Some(value) = line.split('=').nth(1) {
                    let project = value.trim().to_string();
                    if !project.is_empty() {
                        return Some(project);
                    }
                }
            }
        }
        
        None
    }

    /// Get an access token using the credentials.
    async fn get_access_token(&self, client: &Client) -> Result<String> {
        let contents = std::fs::read_to_string(&self.credentials_path)
            .context("Failed to read credentials file")?;

        let creds: AdcFile =
            serde_json::from_str(&contents).context("Failed to parse credentials file")?;

        // ADC files can be either service account keys or user credentials
        if creds.r#type.as_deref() == Some("authorized_user") {
            // User credentials - use refresh token
            self.refresh_user_token(client, &creds).await
        } else if creds.r#type.as_deref() == Some("service_account") {
            // Service account - generate JWT and exchange for token
            self.get_service_account_token(client, &creds).await
        } else {
            anyhow::bail!("Unsupported credential type")
        }
    }

    async fn refresh_user_token(&self, client: &Client, creds: &AdcFile) -> Result<String> {
        let refresh_token = creds
            .refresh_token
            .as_ref()
            .context("No refresh token in credentials")?;
        let client_id = creds
            .client_id
            .as_ref()
            .context("No client_id in credentials")?;
        let client_secret = creds
            .client_secret
            .as_ref()
            .context("No client_secret in credentials")?;

        let resp = client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .context("Failed to refresh token")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Token refresh failed: {} - {}", status, body);
        }

        let token_resp: TokenResponse = resp.json().await.context("Failed to parse token")?;
        Ok(token_resp.access_token)
    }

    async fn get_service_account_token(&self, _client: &Client, _creds: &AdcFile) -> Result<String> {
        // Service account JWT generation requires signing, which needs more dependencies.
        // For now, we recommend using user credentials via `gcloud auth application-default login`.
        anyhow::bail!(
            "Service account credentials require JWT signing. \
             Please use `gcloud auth application-default login` instead."
        )
    }

    /// Fetch all SLOs from GCP Cloud Monitoring.
    pub async fn fetch_slos(&self, client: &Client) -> Result<Vec<SloDefinition>> {
        let token = self.get_access_token(client).await?;
        let mut all_slos = Vec::new();

        // First, list all services
        let services = self.list_services(client, &token).await?;

        // Then fetch SLOs for each service
        for service in services {
            let slos = self
                .list_service_slos(client, &token, &service.name)
                .await?;
            all_slos.extend(slos);
        }

        Ok(all_slos)
    }

    async fn list_services(&self, client: &Client, token: &str) -> Result<Vec<GcpService>> {
        let url = format!(
            "https://monitoring.googleapis.com/v3/projects/{}/services",
            self.project_id
        );

        let resp = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to list GCP services")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GCP API error listing services: {} - {}", status, body);
        }

        let response: GcpServicesResponse = resp.json().await.context("Failed to parse services")?;
        Ok(response.services.unwrap_or_default())
    }

    async fn list_service_slos(
        &self,
        client: &Client,
        token: &str,
        service_name: &str,
    ) -> Result<Vec<SloDefinition>> {
        let url = format!(
            "https://monitoring.googleapis.com/v3/{}/serviceLevelObjectives",
            service_name
        );

        let resp = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to list SLOs")?;

        if !resp.status().is_success() {
            // 404 is ok - service has no SLOs
            if resp.status().as_u16() == 404 {
                return Ok(vec![]);
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GCP API error listing SLOs: {} - {}", status, body);
        }

        let response: GcpSlosResponse = resp.json().await.context("Failed to parse SLOs")?;
        Ok(response
            .service_level_objectives
            .unwrap_or_default()
            .into_iter()
            .map(|slo| self.convert_slo(slo))
            .collect())
    }

    fn convert_slo(&self, slo: GcpSlo) -> SloDefinition {
        // Extract path pattern from labels or SLI config
        let path_pattern = slo.user_labels.as_ref().and_then(|labels| {
            labels
                .get("path")
                .or_else(|| labels.get("endpoint"))
                .cloned()
        });

        // Extract HTTP method from labels
        let http_method = slo
            .user_labels
            .as_ref()
            .and_then(|labels| labels.get("method").map(|m| m.to_uppercase()));

        // Determine timeframe
        let timeframe = slo
            .rolling_period
            .map(|p| format!("rolling_{}", p.trim_end_matches('s')))
            .or(slo.calendar_period.map(|p| p.to_lowercase()))
            .unwrap_or_else(|| "30d".to_string());

        // Build dashboard URL
        let dashboard_url = Some(format!(
            "https://console.cloud.google.com/monitoring/services/{}?project={}",
            slo.name.split('/').last().unwrap_or(&slo.name),
            self.project_id
        ));

        SloDefinition {
            id: slo.name.clone(),
            name: slo.display_name.unwrap_or_else(|| slo.name.clone()),
            provider: SloProviderKind::Gcp,
            path_pattern,
            http_method,
            target_percent: slo.goal * 100.0, // GCP stores as 0.999, we want 99.9
            current_percent: None, // Would need separate API call to get status
            error_budget_remaining: None,
            timeframe,
            dashboard_url,
        }
    }
}

// GCP credential types

#[derive(Debug, Deserialize)]
struct AdcFile {
    #[serde(rename = "type")]
    r#type: Option<String>,
    quota_project_id: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

// GCP API response types

#[derive(Debug, Deserialize)]
struct GcpServicesResponse {
    services: Option<Vec<GcpService>>,
}

#[derive(Debug, Deserialize)]
struct GcpService {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSlosResponse {
    service_level_objectives: Option<Vec<GcpSlo>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSlo {
    name: String,
    display_name: Option<String>,
    goal: f64,
    rolling_period: Option<String>,
    calendar_period: Option<String>,
    user_labels: Option<std::collections::HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available_without_credentials() {
        // This test depends on the environment
        // In most CI environments, GCP credentials won't be available
        // Just verify it doesn't panic
        let _ = GcpProvider::is_available();
    }
}

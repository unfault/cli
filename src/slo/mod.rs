//! SLO (Service Level Objective) discovery and graph enrichment.
//!
//! This module provides functionality to:
//! 1. Detect available SLO providers from well-known credential locations
//! 2. Fetch SLO definitions from GCP Cloud Monitoring, Datadog, and Dynatrace
//! 3. Match SLOs to HTTP route handlers in the code graph
//! 4. Enrich the graph with SLO nodes and MonitoredBy edges
//!
//! ## Usage
//!
//! ```rust,ignore
//! use unfault::slo::SloEnricher;
//!
//! let enricher = SloEnricher::new();
//! if enricher.any_provider_available() {
//!     let slos = enricher.fetch_all().await?;
//!     enricher.enrich_graph(&mut graph, &slos)?;
//! }
//! ```

mod datadog;
mod dynatrace;
mod gcp;
pub mod matcher;
pub mod types;

use anyhow::Result;
use reqwest::Client;
use unfault_core::graph::CodeGraph;

pub use types::{SloDefinition, SloProviderKind};

use self::datadog::DatadogProvider;
use self::dynatrace::DynatraceProvider;
use self::gcp::GcpProvider;

/// SLO enricher that discovers, fetches, and links SLOs to the code graph.
pub struct SloEnricher {
    client: Client,
    verbose: bool,
}

impl SloEnricher {
    /// Create a new SLO enricher.
    pub fn new(verbose: bool) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, verbose }
    }

    /// Check if any SLO provider credentials are available.
    pub fn any_provider_available(&self) -> bool {
        DatadogProvider::is_available()
            || GcpProvider::is_available()
            || DynatraceProvider::is_available()
    }

    /// Get a list of available provider names.
    pub fn available_providers(&self) -> Vec<&'static str> {
        let mut providers = Vec::new();
        if DatadogProvider::is_available() {
            providers.push("Datadog");
        }
        if GcpProvider::is_available() {
            providers.push("GCP");
        }
        if DynatraceProvider::is_available() {
            providers.push("Dynatrace");
        }
        providers
    }

    /// Fetch SLOs from all available providers.
    ///
    /// Errors from individual providers are logged but don't fail the overall fetch.
    pub async fn fetch_all(&self) -> Result<Vec<SloDefinition>> {
        let mut all_slos = Vec::new();

        // Fetch from Datadog
        if let Some(provider) = DatadogProvider::from_env() {
            match provider.fetch_slos(&self.client).await {
                Ok(slos) => {
                    if self.verbose {
                        eprintln!("  Fetched {} SLOs from Datadog", slos.len());
                    }
                    all_slos.extend(slos);
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("  Warning: Failed to fetch Datadog SLOs: {}", e);
                    }
                }
            }
        }

        // Fetch from GCP
        if let Some(provider) = GcpProvider::from_env() {
            match provider.fetch_slos(&self.client).await {
                Ok(slos) => {
                    if self.verbose {
                        eprintln!("  Fetched {} SLOs from GCP", slos.len());
                    }
                    all_slos.extend(slos);
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("  Warning: Failed to fetch GCP SLOs: {}", e);
                    }
                }
            }
        }

        // Fetch from Dynatrace
        if let Some(provider) = DynatraceProvider::from_env() {
            match provider.fetch_slos(&self.client).await {
                Ok(slos) => {
                    if self.verbose {
                        eprintln!("  Fetched {} SLOs from Dynatrace", slos.len());
                    }
                    all_slos.extend(slos);
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("  Warning: Failed to fetch Dynatrace SLOs: {}", e);
                    }
                }
            }
        }

        Ok(all_slos)
    }

    /// Enrich a code graph with SLO nodes and MonitoredBy edges.
    ///
    /// For each SLO with a path pattern, finds matching HTTP route handlers
    /// and creates edges linking them.
    ///
    /// Returns the number of SLOs added to the graph.
    pub fn enrich_graph(&self, graph: &mut CodeGraph, slos: &[SloDefinition]) -> Result<usize> {
        let mut added = 0;

        for slo in slos {
            // Skip SLOs without a usable path pattern
            if !slo.has_path_pattern() {
                if self.verbose {
                    eprintln!(
                        "  Skipping SLO '{}' (no path pattern)",
                        slo.name
                    );
                }
                continue;
            }

            // Find matching route handlers
            let matching_routes = matcher::find_matching_routes(slo, graph);

            if matching_routes.is_empty() {
                if self.verbose {
                    eprintln!(
                        "  SLO '{}' pattern '{}' matched no routes",
                        slo.name,
                        slo.path_pattern.as_deref().unwrap_or("?")
                    );
                }
                continue;
            }

            if self.verbose {
                eprintln!(
                    "  SLO '{}' matched {} route(s)",
                    slo.name,
                    matching_routes.len()
                );
            }

            // Add SLO node and edges to graph
            graph.add_slo(
                slo.id.clone(),
                slo.name.clone(),
                slo.provider.to_core(),
                slo.path_pattern.clone().unwrap_or_default(),
                slo.http_method.clone(),
                slo.target_percent,
                slo.current_percent,
                slo.error_budget_remaining,
                slo.timeframe.clone(),
                slo.dashboard_url.clone(),
                matching_routes,
            );

            added += 1;
        }

        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enricher_creation() {
        let enricher = SloEnricher::new(false);
        // Just verify it doesn't panic
        let _ = enricher.any_provider_available();
    }
}

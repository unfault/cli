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
                    eprintln!("  Skipping SLO '{}' (no path pattern)", slo.name);
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
                    "  SLO '{}' matched {} route(s):",
                    slo.name,
                    matching_routes.len()
                );
                // Show matched route details
                for idx in &matching_routes {
                    if let Some((http_method, http_path, func_name)) = graph.get_route_info(*idx) {
                        eprintln!(
                            "    → {} {} ({})",
                            http_method.unwrap_or("*".to_string()),
                            http_path,
                            func_name
                        );
                    }
                }
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

    /// Link a service-level SLO to all HTTP route handlers in the graph.
    ///
    /// This is used when an SLO covers an entire service (e.g., Cloud Run)
    /// rather than specific paths.
    ///
    /// Returns the number of routes linked.
    pub fn link_service_slo_to_all_routes(
        &self,
        graph: &mut CodeGraph,
        slo: &SloDefinition,
    ) -> usize {
        let routes = graph.get_http_route_handlers();
        let route_count = routes.len();
        let route_indices: Vec<_> = routes.iter().map(|(idx, _, _)| *idx).collect();

        if route_indices.is_empty() {
            if self.verbose {
                eprintln!("  No HTTP routes found to link to SLO '{}'", slo.name);
            }
            return 0;
        }

        if self.verbose {
            eprintln!("  Linking SLO '{}' to {} route(s):", slo.name, route_count);
            for (idx, http_path, http_method) in &routes {
                if let Some((_, _, func_name)) = graph.get_route_info(*idx) {
                    eprintln!(
                        "    → {} {} ({})",
                        http_method.unwrap_or("*"),
                        http_path,
                        func_name
                    );
                }
            }
        }

        // Drop the borrow before mutating
        drop(routes);

        graph.add_slo(
            slo.id.clone(),
            slo.name.clone(),
            slo.provider.to_core(),
            slo.path_pattern.clone().unwrap_or_else(|| "*".to_string()),
            slo.http_method.clone(),
            slo.target_percent,
            slo.current_percent,
            slo.error_budget_remaining,
            slo.timeframe.clone(),
            slo.dashboard_url.clone(),
            route_indices,
        );

        route_count
    }
}

/// Get service-level SLOs (those without path patterns).
///
/// These are SLOs that apply to an entire service rather than specific paths.
pub fn get_service_level_slos(slos: &[SloDefinition]) -> Vec<&SloDefinition> {
    slos.iter().filter(|s| !s.has_path_pattern()).collect()
}

/// Group SLOs by their service name.
///
/// For GCP, the service name is extracted from the SLO ID:
/// `projects/xxx/services/SERVICE_NAME/serviceLevelObjectives/yyy`
pub fn group_slos_by_service(
    slos: &[SloDefinition],
) -> std::collections::HashMap<String, Vec<&SloDefinition>> {
    let mut groups: std::collections::HashMap<String, Vec<&SloDefinition>> =
        std::collections::HashMap::new();

    for slo in slos {
        let service_name = extract_service_name(&slo.id);
        groups.entry(service_name).or_default().push(slo);
    }

    groups
}

/// Extract the service name from an SLO ID.
///
/// GCP format: `projects/xxx/services/SERVICE_ID/serviceLevelObjectives/yyy`
/// Returns the full service path up to (and including) the service ID.
fn extract_service_name(slo_id: &str) -> String {
    // Find the position of "/serviceLevelObjectives/"
    if let Some(pos) = slo_id.find("/serviceLevelObjectives/") {
        slo_id[..pos].to_string()
    } else {
        // Fallback: use the whole ID
        slo_id.to_string()
    }
}

/// Get a human-friendly display name for a service.
///
/// Extracts just the service ID from the full path.
pub fn get_service_display_name(service_name: &str) -> String {
    // GCP format: projects/xxx/services/SERVICE_ID
    if let Some(pos) = service_name.rfind("/services/") {
        service_name[pos + "/services/".len()..].to_string()
    } else {
        service_name.to_string()
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

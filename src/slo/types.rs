//! SLO type definitions shared across providers.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The provider source for an SLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SloProviderKind {
    /// Google Cloud Monitoring
    Gcp,
    /// Datadog
    Datadog,
    /// Dynatrace
    Dynatrace,
}

impl fmt::Display for SloProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SloProviderKind::Gcp => write!(f, "GCP"),
            SloProviderKind::Datadog => write!(f, "Datadog"),
            SloProviderKind::Dynatrace => write!(f, "Dynatrace"),
        }
    }
}

impl SloProviderKind {
    /// Convert to the core crate's SloProvider type.
    pub fn to_core(&self) -> unfault_core::graph::SloProvider {
        match self {
            SloProviderKind::Gcp => unfault_core::graph::SloProvider::Gcp,
            SloProviderKind::Datadog => unfault_core::graph::SloProvider::Datadog,
            SloProviderKind::Dynatrace => unfault_core::graph::SloProvider::Dynatrace,
        }
    }
}

/// An SLO definition fetched from an observability provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloDefinition {
    /// Unique identifier from the provider
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// The provider source
    pub provider: SloProviderKind,
    /// URL path pattern this SLO monitors (e.g., "/api/users/*")
    /// None if the SLO doesn't specify a path pattern
    pub path_pattern: Option<String>,
    /// HTTP method if specific (e.g., "GET"), None for all methods
    pub http_method: Option<String>,
    /// Target percentage (e.g., 99.9)
    pub target_percent: f64,
    /// Current evaluated percentage (e.g., 99.85)
    pub current_percent: Option<f64>,
    /// Error budget remaining as percentage
    pub error_budget_remaining: Option<f64>,
    /// Evaluation timeframe (e.g., "30d", "7d")
    pub timeframe: String,
    /// Direct link to SLO in provider dashboard
    pub dashboard_url: Option<String>,
}

impl SloDefinition {
    /// Check if this SLO has a usable path pattern for matching.
    pub fn has_path_pattern(&self) -> bool {
        self.path_pattern
            .as_ref()
            .is_some_and(|p| !p.is_empty() && p != "*")
    }
}

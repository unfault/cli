//! # Session Runner
//!
//! Manages the session lifecycle: create session, run analysis, and wait for results.
//! This module orchestrates the API calls and handles session state.

use std::time::Duration;
use tokio::time::sleep;

use crate::api::{
    ApiClient, ApiError, ApiRuleSettings, ApiWorkspaceSettings, ReviewSessionMeta,
    SessionContextInput, SessionEmbedResponse, SessionNewRequest, SessionNewResponse,
    SessionRunRequest, SessionRunResponse, SessionStatusResponse,
};
use crate::session::file_collector::CollectedFiles;
use crate::session::workspace::WorkspaceInfo;
use crate::session::workspace_settings::WorkspaceSettings;

/// Session status values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Created,
    Analyzing,
    Completed,
    Failed,
    Expired,
    Unknown(String),
}

impl From<&str> for SessionStatus {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "created" => SessionStatus::Created,
            "analyzing" => SessionStatus::Analyzing,
            "completed" => SessionStatus::Completed,
            "failed" => SessionStatus::Failed,
            "expired" => SessionStatus::Expired,
            other => SessionStatus::Unknown(other.to_string()),
        }
    }
}

impl SessionStatus {
    /// Check if the session is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionStatus::Completed | SessionStatus::Failed | SessionStatus::Expired
        )
    }
}

/// Configuration for session runner.
#[derive(Debug, Clone)]
pub struct SessionRunnerConfig {
    /// Maximum time to wait for session completion
    pub timeout: Duration,
    /// Interval between status polls
    pub poll_interval: Duration,
}

impl Default for SessionRunnerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes
            poll_interval: Duration::from_secs(2),
        }
    }
}

/// Result of a completed session.
#[derive(Debug, Clone)]
pub struct SessionResult {
    /// Session ID
    pub session_id: String,
    /// Final status
    pub status: SessionStatus,
    /// Analysis response (if completed successfully)
    pub response: Option<SessionRunResponse>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Runner for managing session lifecycle.
pub struct SessionRunner<'a> {
    client: &'a ApiClient,
    api_key: &'a str,
    config: SessionRunnerConfig,
}

impl<'a> SessionRunner<'a> {
    /// Create a new session runner.
    ///
    /// # Arguments
    ///
    /// * `client` - API client for making requests
    /// * `api_key` - API key for authentication
    pub fn new(client: &'a ApiClient, api_key: &'a str) -> Self {
        Self {
            client,
            api_key,
            config: SessionRunnerConfig::default(),
        }
    }

    /// Create a new session runner with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `client` - API client for making requests
    /// * `api_key` - API key for authentication
    /// * `config` - Runner configuration
    pub fn with_config(
        client: &'a ApiClient,
        api_key: &'a str,
        config: SessionRunnerConfig,
    ) -> Self {
        Self {
            client,
            api_key,
            config,
        }
    }

    /// Create a new analysis session.
    ///
    /// # Arguments
    ///
    /// * `workspace_info` - Information about the workspace
    /// * `requested_dimensions` - Optional dimensions to focus on
    ///
    /// # Returns
    ///
    /// * `Ok(SessionNewResponse)` - Session created successfully
    /// * `Err(ApiError)` - Failed to create session
    pub async fn create_session(
        &self,
        workspace_info: &WorkspaceInfo,
        requested_dimensions: Option<Vec<String>>,
    ) -> Result<SessionNewResponse, ApiError> {
        // Convert workspace settings to API format
        let workspace_settings = workspace_info
            .workspace_settings()
            .map(convert_to_api_settings);

        let request = SessionNewRequest {
            workspace: workspace_info.to_workspace_descriptor(),
            requested_dimensions,
            workspace_settings,
        };

        self.client.create_session(self.api_key, &request).await
    }

    /// Run analysis on a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    /// * `workspace_info` - Information about the workspace
    /// * `collected_files` - Files to analyze
    /// * `dimension` - Dimension for analysis context
    ///
    /// # Returns
    ///
    /// * `Ok(SessionRunResponse)` - Analysis completed
    /// * `Err(ApiError)` - Failed to run analysis
    pub async fn run_analysis(
        &self,
        session_id: &str,
        workspace_info: &WorkspaceInfo,
        collected_files: &CollectedFiles,
        dimension: &str,
    ) -> Result<SessionRunResponse, ApiError> {
        let meta = ReviewSessionMeta {
            label: workspace_info.label.clone(),
            languages: workspace_info.language_strings(),
            framework_guesses: workspace_info.framework_strings(),
            layout: Some(workspace_info.layout.clone()),
            git: None,
            requested_dimensions: vec![dimension.to_string()],
        };

        let contexts = vec![SessionContextInput {
            id: "ctx_workspace".to_string(),
            label: "Workspace".to_string(),
            dimension: dimension.to_string(),
            files: collected_files.files.clone(),
        }];

        let request = SessionRunRequest { meta, contexts };

        self.client
            .run_analysis(self.api_key, session_id, &request)
            .await
    }

    /// Run analysis with multiple contexts.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    /// * `workspace_info` - Information about the workspace
    /// * `contexts` - Analysis contexts with files
    ///
    /// # Returns
    ///
    /// * `Ok(SessionRunResponse)` - Analysis completed
    /// * `Err(ApiError)` - Failed to run analysis
    pub async fn run_analysis_with_contexts(
        &self,
        session_id: &str,
        workspace_info: &WorkspaceInfo,
        contexts: Vec<SessionContextInput>,
    ) -> Result<SessionRunResponse, ApiError> {
        let dimensions: Vec<String> = contexts.iter().map(|c| c.dimension.clone()).collect();

        let meta = ReviewSessionMeta {
            label: workspace_info.label.clone(),
            languages: workspace_info.language_strings(),
            framework_guesses: workspace_info.framework_strings(),
            layout: Some(workspace_info.layout.clone()),
            git: None,
            requested_dimensions: dimensions,
        };

        let request = SessionRunRequest { meta, contexts };

        self.client
            .run_analysis(self.api_key, session_id, &request)
            .await
    }

    /// Get session status.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    ///
    /// # Returns
    ///
    /// * `Ok(SessionStatusResponse)` - Session status
    /// * `Err(ApiError)` - Failed to get status
    pub async fn get_status(&self, session_id: &str) -> Result<SessionStatusResponse, ApiError> {
        self.client
            .get_session_status(self.api_key, session_id)
            .await
    }

    /// Generate embeddings for a completed session.
    ///
    /// Embeddings enable RAG features like semantic search and AI insights.
    /// This endpoint is idempotent - calling it multiple times is safe.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    ///
    /// # Returns
    ///
    /// * `Ok(SessionEmbedResponse)` - Embeddings generated (or already existed)
    /// * `Err(ApiError)` - Failed to generate embeddings
    pub async fn generate_embeddings(
        &self,
        session_id: &str,
    ) -> Result<SessionEmbedResponse, ApiError> {
        self.client
            .generate_embeddings(self.api_key, session_id)
            .await
    }

    /// Wait for session to complete.
    ///
    /// Polls the session status until it reaches a terminal state or times out.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    ///
    /// # Returns
    ///
    /// * `Ok(SessionStatus)` - Final session status
    /// * `Err(ApiError)` - Failed to wait for completion or timed out
    pub async fn wait_for_completion(&self, session_id: &str) -> Result<SessionStatus, ApiError> {
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > self.config.timeout {
                return Err(ApiError::ClientError {
                    status: 408,
                    message: format!(
                        "Session timed out after {:?}. Session ID: {}",
                        self.config.timeout, session_id
                    ),
                });
            }

            let status_response = self.get_status(session_id).await?;
            let status = SessionStatus::from(status_response.status.as_str());

            if status.is_terminal() {
                return Ok(status);
            }

            sleep(self.config.poll_interval).await;
        }
    }

    /// Execute a complete analysis workflow.
    ///
    /// This is a convenience method that:
    /// 1. Creates a session
    /// 2. Runs analysis
    /// 3. Returns the result
    ///
    /// # Arguments
    ///
    /// * `workspace_info` - Information about the workspace
    /// * `collected_files` - Files to analyze
    /// * `dimension` - Dimension for analysis
    ///
    /// # Returns
    ///
    /// * `Ok(SessionResult)` - Complete session result
    /// * `Err(ApiError)` - Failed at any step
    pub async fn execute(
        &self,
        workspace_info: &WorkspaceInfo,
        collected_files: &CollectedFiles,
        dimension: &str,
    ) -> Result<SessionResult, ApiError> {
        // Step 1: Create session
        let session_response = self.create_session(workspace_info, None).await?;
        let session_id = session_response.session_id.clone();

        // Step 2: Run analysis
        let run_response = self
            .run_analysis(&session_id, workspace_info, collected_files, dimension)
            .await?;

        let status = SessionStatus::from(run_response.status.as_str());

        Ok(SessionResult {
            session_id,
            status,
            response: Some(run_response),
            error_message: None,
        })
    }

    /// Execute analysis with custom dimensions.
    ///
    /// # Arguments
    ///
    /// * `workspace_info` - Information about the workspace
    /// * `collected_files` - Files to analyze
    /// * `dimensions` - Dimensions to analyze
    ///
    /// # Returns
    ///
    /// * `Ok(SessionResult)` - Complete session result
    /// * `Err(ApiError)` - Failed at any step
    pub async fn execute_with_dimensions(
        &self,
        workspace_info: &WorkspaceInfo,
        collected_files: &CollectedFiles,
        dimensions: &[&str],
    ) -> Result<SessionResult, ApiError> {
        // Step 1: Create session with requested dimensions
        let requested_dimensions = Some(dimensions.iter().map(|s| s.to_string()).collect());
        let session_response = self
            .create_session(workspace_info, requested_dimensions)
            .await?;
        let session_id = session_response.session_id.clone();

        // Step 2: Build contexts for each dimension
        let contexts: Vec<SessionContextInput> = dimensions
            .iter()
            .map(|dim| SessionContextInput {
                id: format!("ctx_{}", dim),
                label: format!("{} Analysis", capitalize(dim)),
                dimension: dim.to_string(),
                files: collected_files.files.clone(),
            })
            .collect();

        // Step 3: Run analysis
        let run_response = self
            .run_analysis_with_contexts(&session_id, workspace_info, contexts)
            .await?;

        let status = SessionStatus::from(run_response.status.as_str());

        Ok(SessionResult {
            session_id,
            status,
            response: Some(run_response),
            error_message: None,
        })
    }
}

/// Capitalize the first letter of a string.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Convert workspace settings to API format.
fn convert_to_api_settings(settings: &WorkspaceSettings) -> ApiWorkspaceSettings {
    ApiWorkspaceSettings {
        profile: settings.profile.clone(),
        dimensions: settings.dimensions.clone(),
        rules: ApiRuleSettings {
            exclude: settings.rules.exclude.clone(),
            include: settings.rules.include.clone(),
            severity: settings.rules.severity.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_status_from_str() {
        assert_eq!(SessionStatus::from("created"), SessionStatus::Created);
        assert_eq!(SessionStatus::from("analyzing"), SessionStatus::Analyzing);
        assert_eq!(SessionStatus::from("completed"), SessionStatus::Completed);
        assert_eq!(SessionStatus::from("failed"), SessionStatus::Failed);
        assert_eq!(SessionStatus::from("expired"), SessionStatus::Expired);
        assert_eq!(SessionStatus::from("CREATED"), SessionStatus::Created);
        assert_eq!(
            SessionStatus::from("unknown_status"),
            SessionStatus::Unknown("unknown_status".to_string())
        );
    }

    #[test]
    fn test_session_status_is_terminal() {
        assert!(!SessionStatus::Created.is_terminal());
        assert!(!SessionStatus::Analyzing.is_terminal());
        assert!(SessionStatus::Completed.is_terminal());
        assert!(SessionStatus::Failed.is_terminal());
        assert!(SessionStatus::Expired.is_terminal());
        assert!(!SessionStatus::Unknown("other".to_string()).is_terminal());
    }

    #[test]
    fn test_session_runner_config_default() {
        let config = SessionRunnerConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(300));
        assert_eq!(config.poll_interval, Duration::from_secs(2));
    }

    #[test]
    fn test_capitalize() {
        assert_eq!(capitalize("stability"), "Stability");
        assert_eq!(capitalize("PERFORMANCE"), "PERFORMANCE");
        assert_eq!(capitalize(""), "");
        assert_eq!(capitalize("a"), "A");
    }

    // Integration tests would require mocking the API client
    // These are tested at a higher level in the commands module
}

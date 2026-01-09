//! # Configuration Management
//!
//! This module handles loading and saving CLI configuration, including API keys,
//! server URLs, and LLM configuration for Insights feature.
//!
//! ## Configuration File Location
//!
//! All platforms: `$HOME/.config/unfault/config.json`
//!
//! On Windows, uses `%USERPROFILE%\.config\unfault\config.json` if `$HOME` is not set.
//!
//! ## LLM Configuration
//!
//! The CLI supports BYOLLM (Bring Your Own LLM) for generating AI insights:
//! - OpenAI (GPT-4, GPT-3.5)
//! - Anthropic (Claude)
//! - Ollama (local models)
//! - Custom endpoints

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Default API base URL
const DEFAULT_BASE_URL: &str = "https://app.unfault.dev";

/// Environment variable for overriding the base URL
const BASE_URL_ENV_VAR: &str = "UNFAULT_BASE_URL";

/// LLM configuration for AI-powered insights
///
/// Stores the configuration for the user's LLM provider (BYOLLM).
///
/// # Supported Providers
///
/// - `openai`: OpenAI API (GPT-4, GPT-3.5)
/// - `anthropic`: Anthropic API (Claude)
/// - `ollama`: Local Ollama instance
/// - `custom`: Custom OpenAI-compatible endpoint
///
/// # Example
///
/// ```rust
/// use unfault::config::LlmConfig;
///
/// let config = LlmConfig {
///     provider: "openai".to_string(),
///     endpoint: "https://api.openai.com/v1".to_string(),
///     model: "gpt-4".to_string(),
///     api_key: None,
///     api_key_env: Some("OPENAI_API_KEY".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// LLM provider (openai, anthropic, ollama, custom)
    pub provider: String,
    /// API endpoint URL
    pub endpoint: String,
    /// Model name (e.g., gpt-4, claude-3-opus)
    pub model: String,
    /// API key (encrypted or plaintext)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Environment variable name for API key (preferred over api_key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
}

impl LlmConfig {
    /// Create a new OpenAI configuration
    pub fn openai(model: &str) -> Self {
        Self {
            provider: "openai".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: Some("OPENAI_API_KEY".to_string()),
        }
    }

    /// Create a new Anthropic configuration
    pub fn anthropic(model: &str) -> Self {
        Self {
            provider: "anthropic".to_string(),
            endpoint: "https://api.anthropic.com/v1".to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: Some("ANTHROPIC_API_KEY".to_string()),
        }
    }

    /// Create a new Ollama configuration
    pub fn ollama(endpoint: &str, model: &str) -> Self {
        Self {
            provider: "ollama".to_string(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: None,
        }
    }

    /// Create a custom configuration
    pub fn custom(endpoint: &str, model: &str) -> Self {
        Self {
            provider: "custom".to_string(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: None,
        }
    }

    /// Get the API key from environment or config
    pub fn get_api_key(&self) -> Option<String> {
        // First try environment variable
        if let Some(ref env_var) = self.api_key_env {
            if let Ok(key) = std::env::var(env_var) {
                return Some(key);
            }
        }
        // Fall back to stored key
        self.api_key.clone()
    }

    /// Check if the LLM is configured and ready to use
    pub fn is_ready(&self) -> bool {
        // Ollama doesn't require an API key
        if self.provider == "ollama" {
            return true;
        }
        // Other providers require an API key
        self.get_api_key().is_some()
    }

    /// Get a masked version of the API key for display
    pub fn masked_api_key(&self) -> Option<String> {
        self.get_api_key().map(|key| {
            if key.len() > 8 {
                format!("{}...{}", &key[..4], &key[key.len() - 4..])
            } else {
                "****".to_string()
            }
        })
    }
}

/// CLI configuration
///
/// Stores authentication credentials, server configuration, and LLM settings.
///
/// # Example
///
/// ```rust
/// use unfault::config::Config;
///
/// let config = Config::new("sk_live_abc123".to_string());
/// config.save().expect("Failed to save config");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API key for authentication
    pub api_key: String,
    /// Base URL for the API (stored in config file)
    #[serde(default = "stored_default_base_url")]
    stored_base_url: String,
    /// LLM configuration for AI-powered insights (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmConfig>,
    /// Workspace to GCP service mappings for SLO linking
    /// Key: workspace_id (e.g., "wks_abc123")
    /// Value: GCP service name (e.g., "projects/xxx/services/api-service")
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub workspace_services: std::collections::HashMap<String, String>,
}

/// Default base URL for storage (without env var override)
fn stored_default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

impl Config {
    /// Get the effective base URL
    ///
    /// Environment variable `UNFAULT_BASE_URL` takes precedence over the config file.
    pub fn base_url(&self) -> String {
        std::env::var(BASE_URL_ENV_VAR).unwrap_or_else(|_| self.stored_base_url.clone())
    }
}

impl Config {
    /// Create a new configuration with an API key
    ///
    /// Uses the default base URL.
    ///
    /// # Arguments
    ///
    /// * `api_key` - The API key for authentication
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            stored_base_url: DEFAULT_BASE_URL.to_string(),
            llm: None,
            workspace_services: std::collections::HashMap::new(),
        }
    }

    /// Create a new configuration with an API key and custom base URL
    ///
    /// # Arguments
    ///
    /// * `api_key` - The API key for authentication
    /// * `base_url` - The base URL for the API (stored in config file)
    pub fn new_with_url(api_key: String, base_url: String) -> Self {
        Self {
            api_key,
            stored_base_url: base_url,
            llm: None,
            workspace_services: std::collections::HashMap::new(),
        }
    }

    /// Set the LLM configuration
    pub fn with_llm(mut self, llm_config: LlmConfig) -> Self {
        self.llm = Some(llm_config);
        self
    }

    /// Remove the LLM configuration
    pub fn remove_llm(&mut self) {
        self.llm = None;
    }

    /// Check if LLM is configured
    pub fn has_llm(&self) -> bool {
        self.llm.is_some()
    }

    /// Check if LLM is configured and ready to use
    pub fn llm_ready(&self) -> bool {
        self.llm.as_ref().map(|l| l.is_ready()).unwrap_or(false)
    }

    /// Get the GCP service mapped to a workspace
    pub fn get_workspace_service(&self, workspace_id: &str) -> Option<&String> {
        self.workspace_services.get(workspace_id)
    }

    /// Set the GCP service for a workspace
    pub fn set_workspace_service(&mut self, workspace_id: String, service_name: String) {
        self.workspace_services.insert(workspace_id, service_name);
    }

    /// Remove the GCP service mapping for a workspace
    pub fn remove_workspace_service(&mut self, workspace_id: &str) -> Option<String> {
        self.workspace_services.remove(workspace_id)
    }

    /// Load configuration from the default config file
    ///
    /// # Returns
    ///
    /// * `Ok(Config)` - Successfully loaded configuration
    /// * `Err(_)` - Configuration file not found or invalid
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Save configuration to the default config file
    ///
    /// Creates the config directory if it doesn't exist.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully saved configuration
    /// * `Err(_)` - Failed to create directory or write file
    pub fn save(&self) -> Result<()> {
        let path = config_path()?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let contents = serde_json::to_string_pretty(self).context("Failed to serialize config")?;
        fs::write(&path, contents)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    /// Check if a configuration file exists
    pub fn exists() -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Delete the configuration file
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully deleted or file didn't exist
    /// * `Err(_)` - Failed to delete file
    pub fn delete() -> Result<()> {
        let path = config_path()?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to delete config file: {}", path.display()))?;
        }
        Ok(())
    }
}

/// Get the default base URL
///
/// Checks the `UNFAULT_BASE_URL` environment variable first,
/// then falls back to the default production URL.
pub fn default_base_url() -> String {
    std::env::var(BASE_URL_ENV_VAR).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string())
}

/// Get the path to the configuration file
///
/// Uses platform-specific config directories:
/// - Linux: `~/.config/unfault/config.json`
/// - macOS: `~/Library/Application Support/unfault/config.json`
/// - Windows: `%APPDATA%\unfault\config.json`
fn config_path() -> Result<PathBuf> {
    let config_dir = dirs_config_dir().context("Could not determine config directory")?;
    Ok(config_dir.join("unfault").join("config.json"))
}

/// Get the config directory
///
/// Uses `$HOME/.config` on all platforms for consistency.
fn dirs_config_dir() -> Option<PathBuf> {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .or_else(|| std::env::var("USERPROFILE").ok())
                .map(|h| PathBuf::from(h).join(".config"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;
    use tempfile::TempDir;

    #[test]
    fn test_config_new() {
        let config = Config::new("sk_live_test123".to_string());
        assert_eq!(config.api_key, "sk_live_test123");
    }

    #[test]
    #[serial]
    fn test_config_new_with_url() {
        // Clear env var to test stored URL
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::remove_var(BASE_URL_ENV_VAR) };
        let config = Config::new_with_url(
            "sk_live_test123".to_string(),
            "http://localhost:8000".to_string(),
        );
        assert_eq!(config.api_key, "sk_live_test123");
        assert_eq!(config.base_url(), "http://localhost:8000");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::new_with_url(
            "sk_live_test123".to_string(),
            "https://api.example.com".to_string(),
        );
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("sk_live_test123"));
        assert!(json.contains("https://api.example.com"));
    }

    #[test]
    #[serial]
    fn test_config_deserialization() {
        // Clear env var to test stored URL
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::remove_var(BASE_URL_ENV_VAR) };
        let json = r#"{"api_key":"sk_live_test123","stored_base_url":"https://api.example.com"}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.api_key, "sk_live_test123");
        assert_eq!(config.base_url(), "https://api.example.com");
    }

    #[test]
    fn test_config_deserialization_default_url() {
        let json = r#"{"api_key":"sk_live_test123"}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.api_key, "sk_live_test123");
        // base_url should use default
    }

    #[test]
    #[serial]
    fn test_default_base_url_without_env() {
        // Clear the env var if set
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::remove_var(BASE_URL_ENV_VAR) };
        let url = default_base_url();
        assert_eq!(url, DEFAULT_BASE_URL);
    }

    #[test]
    #[serial]
    fn test_default_base_url_with_env() {
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::set_var(BASE_URL_ENV_VAR, "http://localhost:9000") };
        let url = default_base_url();
        assert_eq!(url, "http://localhost:9000");
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::remove_var(BASE_URL_ENV_VAR) };
    }

    #[test]
    #[serial]
    fn test_config_save_and_load() {
        // Clear env var to test stored URL
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::remove_var(BASE_URL_ENV_VAR) };

        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join("unfault");
        fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("config.json");

        let config = Config::new_with_url(
            "sk_live_test_save_load".to_string(),
            "http://test.example.com".to_string(),
        );

        // Save directly to temp path
        let contents = serde_json::to_string_pretty(&config).unwrap();
        fs::write(&config_path, contents).unwrap();

        // Load from temp path
        let loaded_contents = fs::read_to_string(&config_path).unwrap();
        let loaded: Config = serde_json::from_str(&loaded_contents).unwrap();

        assert_eq!(loaded.api_key, "sk_live_test_save_load");
        assert_eq!(loaded.base_url(), "http://test.example.com");
    }

    #[test]
    #[serial]
    fn test_env_var_takes_precedence() {
        let config = Config::new_with_url(
            "sk_live_test123".to_string(),
            "http://stored.example.com".to_string(),
        );

        // Set env var - should take precedence
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::set_var(BASE_URL_ENV_VAR, "http://env.example.com") };
        assert_eq!(config.base_url(), "http://env.example.com");

        // Clear env var - should fall back to stored URL
        // SAFETY: Test code runs serially with serial_test, no other threads access this env var
        unsafe { env::remove_var(BASE_URL_ENV_VAR) };
        assert_eq!(config.base_url(), "http://stored.example.com");
    }

    #[test]
    fn test_config_exists() {
        // This test depends on whether a config file exists on the system
        // Just verify it doesn't panic
        let _ = Config::exists();
    }
}

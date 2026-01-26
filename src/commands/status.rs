//! # Status Command
//!
//! Implements the status command for checking authentication and API status.
//!
//! ## Usage
//!
//! ```bash
//! unfault status
//! ```

use anyhow::Result;
use colored::Colorize;

use crate::api::ApiClient;
use crate::commands::addon::{AddonStatus, detect_fault};
use crate::config::Config;
use crate::exit_codes::*;

/// Execute the status command
///
/// Checks authentication status and API connectivity.
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Everything is configured and working
/// * `Ok(EXIT_CONFIG_ERROR)` - Not logged in or configuration error
/// * `Ok(EXIT_NETWORK_ERROR)` - Cannot reach the API
/// * `Ok(EXIT_AUTH_ERROR)` - API key is invalid
pub async fn execute() -> Result<i32> {
    println!("{}", "Unfault CLI Status".bold());
    println!("{}", "─".repeat(40).dimmed());
    println!();

    // Check configuration
    let config = match Config::load() {
        Ok(config) => {
            println!(
                "{} Configuration: {}",
                "✓".bright_green().bold(),
                "Found".green()
            );
            Some(config)
        }
        Err(_) => {
            println!("{} Configuration: {}", "✗".red().bold(), "Not found".red());
            println!("  {} Run `unfault login` to authenticate", "→".cyan());
            None
        }
    };

    // Check API connectivity (env var takes precedence over config file)
    let api_url = config
        .as_ref()
        .map(|c| c.base_url())
        .unwrap_or_else(crate::config::default_base_url);

    println!();
    println!("{} API Endpoint: {}", "ℹ".blue(), api_url.cyan());

    let api_client = ApiClient::new(api_url.clone());

    match api_client.health_check().await {
        Ok(true) => {
            println!(
                "{} API Status: {}",
                "✓".bright_green().bold(),
                "Healthy".green()
            );
        }
        Ok(false) => {
            println!(
                "{} API Status: {}",
                "⚠".yellow().bold(),
                "Unhealthy".yellow()
            );
            println!("  {} The API returned a non-success status", "→".cyan());
        }
        Err(e) => {
            println!("{} API Status: {}", "✗".red().bold(), "Unreachable".red());
            println!("  {} {}", "Error:".dimmed(), format!("{}", e).dimmed());
            println!();
            println!("{}", "Possible causes:".yellow());
            println!("  • No internet connection");
            println!("  • API server is down");
            println!("  • Firewall blocking the connection");

            if config.is_none() {
                return Ok(EXIT_CONFIG_ERROR);
            }
            return Ok(EXIT_NETWORK_ERROR);
        }
    }

    // Check authentication if we have a config
    if let Some(config) = config {
        println!();

        // Mask the API key for display
        let masked_key = mask_api_key(&config.api_key);
        println!("{} API Key: {}", "ℹ".blue(), masked_key.dimmed());

        // Try to validate the API key by making a simple authenticated request
        // For now, we just show the key is configured
        // A real implementation would make a /me or /whoami endpoint call
        println!(
            "{} Authentication: {}",
            "✓".bright_green().bold(),
            "Configured".green()
        );

        println!();
        render_addons_status();

        println!();
        println!(
            "{} Ready to analyze code. Run `unfault review` to start.",
            "✓".bright_green().bold()
        );

        Ok(EXIT_SUCCESS)
    } else {
        println!();
        println!(
            "{} Not authenticated. Run `unfault login` to get started.",
            "✗".red().bold()
        );

        println!();
        render_addons_status();

        Ok(EXIT_CONFIG_ERROR)
    }
}

fn render_addons_status() {
    println!("{} {}", "🧩".cyan(), "Addons".bold());

    let fault = detect_fault();
    match fault.status {
        AddonStatus::Installed => {
            let extra = match (&fault.version, &fault.path) {
                (Some(v), Some(p)) => format!("{} ({})", v, p.display()),
                (Some(v), None) => v.clone(),
                (None, Some(p)) => p.display().to_string(),
                (None, None) => "installed".to_string(),
            };
            println!("  {} fault: {}", "✓".bright_green().bold(), extra.green());
        }
        AddonStatus::Missing => {
            println!("  {} fault: {}", "✗".red().bold(), "missing".red());
            println!("    {} Run `unfault addon install fault`", "→".cyan());
        }
    }

    println!("  {} vscode: {}", "ℹ".blue(), "not checked yet".dimmed());
}

/// Mask an API key for display
///
/// Shows the first 8 characters and masks the rest.
fn mask_api_key(key: &str) -> String {
    if key.len() <= 12 {
        return "*".repeat(key.len());
    }

    let visible = &key[..12];
    let masked_len = key.len() - 12;
    format!("{}...{}", visible, "*".repeat(masked_len.min(8)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_api_key_short() {
        let masked = mask_api_key("short");
        assert_eq!(masked, "*****");
    }

    #[test]
    fn test_mask_api_key_normal() {
        let masked = mask_api_key("sk_live_1234567890abcdef1234567890abcdef");
        assert!(masked.starts_with("sk_live_1234"));
        assert!(masked.contains("..."));
        assert!(masked.contains("*"));
    }

    #[test]
    fn test_mask_api_key_exact_boundary() {
        let masked = mask_api_key("123456789012");
        assert_eq!(masked, "************");
    }

    #[test]
    fn test_mask_api_key_just_over_boundary() {
        let masked = mask_api_key("1234567890123");
        assert!(masked.starts_with("123456789012"));
        assert!(masked.contains("..."));
    }
}

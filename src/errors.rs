//! # Error Handling
//!
//! This module provides user-friendly error display functions and error types
//! for the Unfault CLI.

use colored::Colorize;

/// Display a network error with helpful suggestions
///
/// # Arguments
///
/// * `message` - The error message to display
pub fn display_network_error(message: &str) {
    eprintln!("{} Network error: {}", "✗".red().bold(), message);
    eprintln!();
    eprintln!("{}", "Possible causes:".yellow());
    eprintln!("  • No internet connection");
    eprintln!("  • API server is unreachable");
    eprintln!("  • Firewall blocking the connection");
    eprintln!();
    eprintln!(
        "{} Check your connection and try again.",
        "Tip:".cyan().bold()
    );
}

/// Display an authentication error with helpful suggestions
///
/// # Arguments
///
/// * `message` - The error message to display
pub fn display_auth_error(message: &str) {
    eprintln!("{} Authentication error: {}", "✗".red().bold(), message);
    eprintln!();
    eprintln!("{}", "Possible causes:".yellow());
    eprintln!("  • API key is invalid or expired");
    eprintln!("  • You haven't logged in yet");
    eprintln!();
    eprintln!(
        "{} Run `unfault login` to authenticate.",
        "Tip:".cyan().bold()
    );
}

/// Display a configuration error with helpful suggestions
///
/// # Arguments
///
/// * `message` - The error message to display
pub fn display_config_error(message: &str) {
    eprintln!("{} Configuration error: {}", "✗".red().bold(), message);
    eprintln!();
    eprintln!("{}", "Possible causes:".yellow());
    eprintln!("  • Configuration file is corrupted");
    eprintln!("  • Missing required configuration");
    eprintln!();
    eprintln!(
        "{} Run `unfault login` to reconfigure.",
        "Tip:".cyan().bold()
    );
}

/// Display a session error with helpful suggestions
///
/// # Arguments
///
/// * `message` - The error message to display
pub fn display_session_error(message: &str) {
    eprintln!("{} Session error: {}", "✗".red().bold(), message);
    eprintln!();
    eprintln!("{}", "Possible causes:".yellow());
    eprintln!("  • Session has expired");
    eprintln!("  • Session was not found");
    eprintln!("  • Analysis is still in progress");
    eprintln!();
    eprintln!(
        "{} Try running `unfault review` again.",
        "Tip:".cyan().bold()
    );
}

/// Display a service unavailable error with helpful suggestions
///
/// # Arguments
///
/// * `message` - The error message to display
pub fn display_service_error(message: &str) {
    eprintln!("{} Service unavailable: {}", "✗".red().bold(), message);
    eprintln!();
    eprintln!("{}", "Possible causes:".yellow());
    eprintln!("  • API server is under maintenance");
    eprintln!("  • Service is temporarily unavailable");
    eprintln!();
    eprintln!(
        "{} Check https://status.unfault.dev for service status.",
        "Tip:".cyan().bold()
    );
}

/// Display a generic error
///
/// # Arguments
///
/// * `message` - The error message to display
pub fn display_error(message: &str) {
    eprintln!("{} Error: {}", "✗".red().bold(), message);
}

/// Display a warning
///
/// # Arguments
///
/// * `message` - The warning message to display
pub fn display_warning(message: &str) {
    eprintln!("{} Warning: {}", "⚠".yellow().bold(), message);
}

/// Display a success message
///
/// # Arguments
///
/// * `message` - The success message to display
pub fn display_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Display an info message
///
/// # Arguments
///
/// * `message` - The info message to display
pub fn display_info(message: &str) {
    println!("{} {}", "ℹ".blue().bold(), message);
}

#[cfg(test)]
mod tests {
    // Note: These tests just verify the functions don't panic.
    // Actual output testing would require capturing stderr/stdout.

    use super::*;

    #[test]
    fn test_display_network_error_does_not_panic() {
        display_network_error("Connection refused");
    }

    #[test]
    fn test_display_auth_error_does_not_panic() {
        display_auth_error("Invalid API key");
    }

    #[test]
    fn test_display_config_error_does_not_panic() {
        display_config_error("Config file not found");
    }

    #[test]
    fn test_display_session_error_does_not_panic() {
        display_session_error("Session expired");
    }

    #[test]
    fn test_display_service_error_does_not_panic() {
        display_service_error("503 Service Unavailable");
    }

    #[test]
    fn test_display_error_does_not_panic() {
        display_error("Something went wrong");
    }

    #[test]
    fn test_display_warning_does_not_panic() {
        display_warning("This might cause issues");
    }

    #[test]
    fn test_display_success_does_not_panic() {
        display_success("Operation completed");
    }

    #[test]
    fn test_display_info_does_not_panic() {
        display_info("Processing files...");
    }
}

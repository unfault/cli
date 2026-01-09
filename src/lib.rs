//! # Unfault CLI Library
//!
//! This crate provides the core functionality for the Unfault CLI,
//! a tool for analyzing code for production-readiness issues.
//!
//! ## Modules
//!
//! - [`api`] - API client for communicating with the Unfault API
//! - [`commands`] - CLI command implementations
//! - [`config`] - Configuration management
//! - [`errors`] - Error handling and display
//! - [`exit_codes`] - Standard exit codes
//! - [`session`] - Session management for workspace scanning and analysis
//! - [`slo`] - SLO discovery from observability platforms

pub mod api;
pub mod commands;
pub mod config;
pub mod errors;
pub mod exit_codes;
pub mod session;
pub mod slo;

// Re-export commonly used types
pub use api::ApiClient;
pub use config::Config;
pub use session::{FileCollector, SessionRunner, WorkspaceInfo, WorkspaceScanner};

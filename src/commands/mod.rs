//! # CLI Command Implementations
//!
//! This module contains the implementation of all CLI commands.
//! Each submodule represents a top-level command or command group.
//!
//! ## Available Commands
//!
//! - [`ask`] - Query project health using RAG
//! - [`config`] - Manage CLI configuration (LLM settings, etc.)
//! - [`graph`] - Query the code graph for impact analysis, dependencies, and critical files
//! - [`login`] - Device flow authentication
//! - [`lsp`] - Language Server Protocol server for IDE integration
//! - [`review`] - Analyze code for fault-tolerance issues
//! - [`status`] - Check authentication and service configuration status

pub mod addon;
pub mod ask;
pub mod config;
pub mod fault_plan_cmd;
pub mod fault_scenarios_cmd;
pub mod graph;
pub mod login;
pub mod lsp;
pub mod review;
pub mod status;

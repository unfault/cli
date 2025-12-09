//! # CLI Command Implementations
//!
//! This module contains the implementation of all CLI commands.
//! Each submodule represents a top-level command or command group.
//!
//! ## Available Commands
//!
//! - [`ask`] - Query project health using RAG
//! - [`config`] - Manage CLI configuration (LLM settings, etc.)
//! - [`login`] - Device flow authentication
//! - [`review`] - Analyze code for fault-tolerance issues
//! - [`status`] - Check authentication and service configuration status

pub mod ask;
pub mod config;
pub mod login;
pub mod review;
pub mod status;

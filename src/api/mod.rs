//! # API Client Module
//!
//! This module provides the HTTP client for communicating with the Unfault API.

pub mod auth;
pub mod client;
pub mod graph;
pub mod graph_stream;
pub mod llm;
pub mod rag;
pub mod session;

// Re-export commonly used types for convenience
pub use client::{ApiClient, ApiError};
pub use graph::*;
pub use graph_stream::{stream_graph_as_zstd_ndjson, write_graph_as_zstd_ndjson};
pub use llm::{LlmClient, LlmError, build_llm_context};
pub use rag::*;
pub use session::*;

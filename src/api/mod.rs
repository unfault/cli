//! # API Client Module
//!
//! This module provides the HTTP client for communicating with the Unfault API.

pub mod auth;
pub mod client;
pub mod graph;
pub mod graph_stream;
pub mod llm;
pub mod rag;
pub mod semantics_stream;
pub mod session;

// Re-export commonly used types for convenience
pub use client::{ApiClient, ApiError};
pub use graph::*;
pub use graph_stream::{IdContext, encode_edges_chunk, encode_nodes_chunk};
pub use llm::{LlmClient, LlmError, build_llm_context};
pub use rag::*;
pub use semantics_stream::{SemanticsChunker, encode_semantics_chunk};
pub use session::*;

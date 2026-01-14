//! Chunked (resumable) graph encoding for `/api/v1/graph/ingest/chunk`.
//!
//! Wire format per chunk:
//! - Body is zstd-compressed
//! - Decompressed payload is a sequence of framed msgpack records:
//!   - `u32` big-endian length prefix
//!   - msgpack payload (map)
//!
//! Each chunk MUST end with a `chunk_done` control record that includes:
//! - phase, seq
//! - nodes/edges counts in the chunk
//! - checksum: xxh3_64 of all framed bytes before chunk_done
//!
//! ## Node IDs
//!
//! Nodes are identified by stable, globally unique IDs:
//! - Files: `uf:file:v1:{24_hex_chars}` - computed from git remote + path
//! - Functions/Classes: `uf:sym:v1:{24_hex_chars}` - computed from file_id + qualified name
//! - External modules: `ext:{name}` - simple format, not cross-workspace linkable

use std::collections::HashMap;

use serde::Serialize;
use unfault_core::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use unfault_core::parse::ast::FileId;
use xxhash_rust::xxh3::Xxh3;

use crate::session::{compute_file_id, compute_symbol_id};

#[derive(Serialize)]
struct NodeRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,

    node_id: String,
    node_type: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qualified_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    is_async: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_handler: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    http_method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_path: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    var_name: Option<&'a str>,

    // SLO-specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    slo_provider: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slo_path_pattern: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slo_target_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slo_current_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slo_error_budget_remaining: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slo_timeframe: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slo_dashboard_url: Option<&'a str>,
}

#[derive(Serialize)]
struct EdgeRecord {
    #[serde(rename = "type")]
    record_type: &'static str,

    source_node_id: String,
    target_node_id: String,
    edge_type: &'static str,

    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<Vec<String>>,
}

#[derive(Serialize)]
struct ChunkDoneRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    event: &'static str,

    phase: &'static str,
    seq: u32,
    nodes: u32,
    edges: u32,
    checksum: u64,
}

/// Context for computing stable node IDs.
///
/// This struct holds the information needed to compute globally unique,
/// stable identifiers for graph nodes.
pub struct IdContext {
    /// Git remote URL (e.g., "git@github.com:acme/repo.git").
    /// If available, file IDs will be globally unique across machines.
    pub git_remote: Option<String>,
    /// Workspace ID (e.g., "wks_abc123...").
    /// Used as fallback when git_remote is not available.
    pub workspace_id: String,
    /// Map from internal FileId to relative file path.
    file_id_to_path: HashMap<FileId, String>,
    /// Cache: path -> computed file_id (avoids recomputing)
    path_to_file_id: HashMap<String, String>,
}

impl IdContext {
    /// Create a new IdContext from the graph and workspace information.
    pub fn new(graph: &CodeGraph, git_remote: Option<String>, workspace_id: String) -> Self {
        let mut file_id_to_path = HashMap::new();
        for node_idx in graph.graph.node_indices() {
            if let GraphNode::File { file_id, path, .. } = &graph.graph[node_idx] {
                file_id_to_path.insert(*file_id, path.clone());
            }
        }

        Self {
            git_remote,
            workspace_id,
            file_id_to_path,
            path_to_file_id: HashMap::new(),
        }
    }

    /// Get or compute the file_id for a given path.
    fn get_file_id(&mut self, path: &str) -> String {
        if let Some(cached) = self.path_to_file_id.get(path) {
            return cached.clone();
        }

        let file_id = compute_file_id(self.git_remote.as_deref(), &self.workspace_id, path);
        self.path_to_file_id
            .insert(path.to_string(), file_id.clone());
        file_id
    }

    /// Get the file path for an internal FileId.
    fn get_path(&self, file_id: &FileId) -> Option<&String> {
        self.file_id_to_path.get(file_id)
    }
}

fn node_id_for_node(node: &GraphNode, ctx: &mut IdContext) -> String {
    match node {
        GraphNode::File { path, .. } => ctx.get_file_id(path),
        GraphNode::ExternalModule { name, .. } => {
            // External modules use simple format - not cross-workspace linkable
            format!("ext:{name}")
        }
        GraphNode::Function {
            file_id,
            qualified_name,
            name,
            ..
        } => {
            // Clone the path to avoid borrow issues
            let file_path = match ctx.get_path(file_id) {
                Some(p) => p.clone(),
                None => return String::new(),
            };
            let file_node_id = ctx.get_file_id(&file_path);
            let symbol_name = if qualified_name.is_empty() {
                name.as_str()
            } else {
                qualified_name.as_str()
            };
            compute_symbol_id(&file_node_id, symbol_name)
        }
        GraphNode::Class { file_id, name } => {
            // Clone the path to avoid borrow issues
            let file_path = match ctx.get_path(file_id) {
                Some(p) => p.clone(),
                None => return String::new(),
            };
            let file_node_id = ctx.get_file_id(&file_path);
            compute_symbol_id(&file_node_id, name)
        }
        GraphNode::FastApiApp { file_id, var_name } => {
            let file_path = match ctx.get_path(file_id) {
                Some(p) => p.clone(),
                None => return String::new(),
            };
            let file_node_id = ctx.get_file_id(&file_path);
            // Use "fastapi_app:{var_name}" as the symbol name for uniqueness
            compute_symbol_id(&file_node_id, &format!("fastapi_app:{}", var_name))
        }
        GraphNode::FastApiRoute { .. } | GraphNode::FastApiMiddleware { .. } => {
            // Not currently persisted.
            String::new()
        }
        GraphNode::Slo { id, .. } => {
            // SLO nodes use their provider ID directly
            format!("slo:{id}")
        }
    }
}

fn push_frame(buf: &mut Vec<u8>, value: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let payload = rmp_serde::to_vec_named(value)?;
    let len = u32::try_from(payload.len())?;

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);

    buf.extend_from_slice(&frame);
    Ok(frame)
}

/// Encode a chunk of graph nodes into the wire format.
///
/// # Arguments
///
/// * `graph` - The code graph containing nodes to encode
/// * `ctx` - ID context for computing stable node identifiers
/// * `start` - Starting index in the node list
/// * `max_records` - Maximum number of records to include in this chunk
/// * `seq` - Sequence number for this chunk
///
/// # Returns
///
/// Zstd-compressed bytes containing the framed msgpack records.
pub fn encode_nodes_chunk(
    graph: &CodeGraph,
    ctx: &mut IdContext,
    start: usize,
    max_records: usize,
    seq: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(1024 * 1024);
    let mut hasher = Xxh3::new();

    let node_indices: Vec<_> = graph.graph.node_indices().collect();
    let end = (start + max_records).min(node_indices.len());

    let mut nodes = 0u32;

    for idx in &node_indices[start..end] {
        let node = &graph.graph[*idx];
        let node_id = node_id_for_node(node, ctx);
        if node_id.is_empty() {
            continue;
        }

        let frame = match node {
            GraphNode::File { path, language, .. } => push_frame(
                &mut raw,
                &NodeRecord {
                    record_type: "node",
                    node_id,
                    node_type: "file",
                    path: Some(path),
                    language: Some(format!("{:?}", language)),
                    name: None,
                    qualified_name: None,
                    file_path: None,
                    is_async: None,
                    is_handler: None,
                    http_method: None,
                    http_path: None,
                    category: None,
                    var_name: None,
                    slo_provider: None,
                    slo_path_pattern: None,
                    slo_target_percent: None,
                    slo_current_percent: None,
                    slo_error_budget_remaining: None,
                    slo_timeframe: None,
                    slo_dashboard_url: None,
                },
            )?,
            GraphNode::ExternalModule { name, category } => push_frame(
                &mut raw,
                &NodeRecord {
                    record_type: "node",
                    node_id,
                    node_type: "external_module",
                    path: None,
                    language: None,
                    name: Some(name),
                    qualified_name: None,
                    file_path: None,
                    is_async: None,
                    is_handler: None,
                    http_method: None,
                    http_path: None,
                    category: Some(format!("{:?}", category)),
                    var_name: None,
                    slo_provider: None,
                    slo_path_pattern: None,
                    slo_target_percent: None,
                    slo_current_percent: None,
                    slo_error_budget_remaining: None,
                    slo_timeframe: None,
                    slo_dashboard_url: None,
                },
            )?,
            GraphNode::Function {
                file_id,
                name,
                qualified_name,
                is_async,
                is_handler,
                http_method,
                http_path,
            } => {
                let file_path = ctx.get_path(file_id).cloned();
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "function",
                        path: None,
                        language: None,
                        name: Some(name),
                        qualified_name: if qualified_name.is_empty() {
                            None
                        } else {
                            Some(qualified_name.as_str())
                        },
                        file_path,
                        is_async: Some(*is_async),
                        is_handler: Some(*is_handler),
                        http_method: http_method.as_deref(),
                        http_path: http_path.as_deref(),
                        category: None,
                        var_name: None,
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?
            }
            GraphNode::Class { file_id, name } => {
                let file_path = ctx.get_path(file_id).cloned();
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "class",
                        path: None,
                        language: None,
                        name: Some(name),
                        qualified_name: None,
                        file_path,
                        is_async: None,
                        is_handler: None,
                        http_method: None,
                        http_path: None,
                        category: None,
                        var_name: None,
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?
            }
            GraphNode::FastApiApp { file_id, var_name } => {
                let file_path = ctx.get_path(file_id).cloned();
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "fastapi_app",
                        path: None,
                        language: None,
                        name: None,
                        qualified_name: None,
                        file_path,
                        is_async: None,
                        is_handler: None,
                        http_method: None,
                        http_path: None,
                        category: None,
                        var_name: Some(var_name),
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?
            }
            GraphNode::FastApiRoute { .. } | GraphNode::FastApiMiddleware { .. } => continue,
            GraphNode::Slo {
                name,
                provider,
                path_pattern,
                http_method,
                target_percent,
                current_percent,
                error_budget_remaining,
                timeframe,
                dashboard_url,
                ..
            } => {
                let provider_str = match provider {
                    unfault_core::graph::SloProvider::Gcp => "gcp",
                    unfault_core::graph::SloProvider::Datadog => "datadog",
                    unfault_core::graph::SloProvider::Dynatrace => "dynatrace",
                };
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "slo",
                        path: None,
                        language: None,
                        name: Some(name),
                        qualified_name: None,
                        file_path: None,
                        is_async: None,
                        is_handler: None,
                        http_method: http_method.as_deref(),
                        http_path: None,
                        category: None,
                        var_name: None,
                        slo_provider: Some(provider_str),
                        slo_path_pattern: Some(path_pattern),
                        slo_target_percent: Some(*target_percent),
                        slo_current_percent: *current_percent,
                        slo_error_budget_remaining: *error_budget_remaining,
                        slo_timeframe: Some(timeframe),
                        slo_dashboard_url: dashboard_url.as_deref(),
                    },
                )?
            }
        };

        hasher.update(&frame);
        nodes += 1;
    }

    let checksum = hasher.digest();

    push_frame(
        &mut raw,
        &ChunkDoneRecord {
            record_type: "control",
            event: "chunk_done",
            phase: "nodes",
            seq,
            nodes,
            edges: 0,
            checksum,
        },
    )?;

    Ok(zstd::stream::encode_all(std::io::Cursor::new(raw), 3)?)
}

/// Control record for nodes_done/edges_done events (no sequence/checksum)
#[derive(Serialize)]
struct ControlRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    event: &'static str,
}

/// Encode the full graph into a single stream for PATCH endpoint.
///
/// This produces the same wire format as the chunked ingest, but as a single
/// payload suitable for the PATCH /api/v1/graph/ingest endpoint.
///
/// Format:
/// - All node records
/// - nodes_done control record
/// - All edge records
/// - edges_done control record
///
/// # Arguments
///
/// * `graph` - The code graph to encode (typically just changed files)
/// * `ctx` - ID context for computing stable node identifiers
///
/// # Returns
///
/// Zstd-compressed bytes containing the framed msgpack records.
pub fn encode_graph_stream(
    graph: &CodeGraph,
    mut ctx: IdContext,
) -> anyhow::Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(512 * 1024);

    // Encode all nodes
    for node_idx in graph.graph.node_indices() {
        let node = &graph.graph[node_idx];
        let node_id = node_id_for_node(node, &mut ctx);
        if node_id.is_empty() {
            continue;
        }

        match node {
            GraphNode::File { path, language, .. } => {
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "file",
                        path: Some(path),
                        language: Some(format!("{:?}", language)),
                        name: None,
                        qualified_name: None,
                        file_path: None,
                        is_async: None,
                        is_handler: None,
                        http_method: None,
                        http_path: None,
                        category: None,
                        var_name: None,
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?;
            }
            GraphNode::ExternalModule { name, category } => {
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "external_module",
                        path: None,
                        language: None,
                        name: Some(name),
                        qualified_name: None,
                        file_path: None,
                        is_async: None,
                        is_handler: None,
                        http_method: None,
                        http_path: None,
                        category: Some(format!("{:?}", category)),
                        var_name: None,
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?;
            }
            GraphNode::Function {
                file_id,
                name,
                qualified_name,
                is_async,
                is_handler,
                http_method,
                http_path,
            } => {
                let file_path = ctx.get_path(file_id).cloned();
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "function",
                        path: None,
                        language: None,
                        name: Some(name),
                        qualified_name: if qualified_name.is_empty() {
                            None
                        } else {
                            Some(qualified_name.as_str())
                        },
                        file_path,
                        is_async: Some(*is_async),
                        is_handler: Some(*is_handler),
                        http_method: http_method.as_deref(),
                        http_path: http_path.as_deref(),
                        category: None,
                        var_name: None,
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?;
            }
            GraphNode::Class { file_id, name } => {
                let file_path = ctx.get_path(file_id).cloned();
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "class",
                        path: None,
                        language: None,
                        name: Some(name),
                        qualified_name: None,
                        file_path,
                        is_async: None,
                        is_handler: None,
                        http_method: None,
                        http_path: None,
                        category: None,
                        var_name: None,
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?;
            }
            GraphNode::FastApiApp { file_id, var_name } => {
                let file_path = ctx.get_path(file_id).cloned();
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "fastapi_app",
                        path: None,
                        language: None,
                        name: None,
                        qualified_name: None,
                        file_path,
                        is_async: None,
                        is_handler: None,
                        http_method: None,
                        http_path: None,
                        category: None,
                        var_name: Some(var_name),
                        slo_provider: None,
                        slo_path_pattern: None,
                        slo_target_percent: None,
                        slo_current_percent: None,
                        slo_error_budget_remaining: None,
                        slo_timeframe: None,
                        slo_dashboard_url: None,
                    },
                )?;
            }
            GraphNode::FastApiRoute { .. } | GraphNode::FastApiMiddleware { .. } => continue,
            GraphNode::Slo {
                name,
                provider,
                path_pattern,
                http_method,
                target_percent,
                current_percent,
                error_budget_remaining,
                timeframe,
                dashboard_url,
                ..
            } => {
                let provider_str = match provider {
                    unfault_core::graph::SloProvider::Gcp => "gcp",
                    unfault_core::graph::SloProvider::Datadog => "datadog",
                    unfault_core::graph::SloProvider::Dynatrace => "dynatrace",
                };
                push_frame(
                    &mut raw,
                    &NodeRecord {
                        record_type: "node",
                        node_id,
                        node_type: "slo",
                        path: None,
                        language: None,
                        name: Some(name),
                        qualified_name: None,
                        file_path: None,
                        is_async: None,
                        is_handler: None,
                        http_method: http_method.as_deref(),
                        http_path: None,
                        category: None,
                        var_name: None,
                        slo_provider: Some(provider_str),
                        slo_path_pattern: Some(path_pattern),
                        slo_target_percent: Some(*target_percent),
                        slo_current_percent: *current_percent,
                        slo_error_budget_remaining: *error_budget_remaining,
                        slo_timeframe: Some(timeframe),
                        slo_dashboard_url: dashboard_url.as_deref(),
                    },
                )?;
            }
        }
    }

    // nodes_done control record
    push_frame(
        &mut raw,
        &ControlRecord {
            record_type: "control",
            event: "nodes_done",
        },
    )?;

    // Encode all edges
    for edge_idx in graph.graph.edge_indices() {
        let Some((source, target)) = graph.graph.edge_endpoints(edge_idx) else {
            continue;
        };

        let source_node = &graph.graph[source];
        let target_node = &graph.graph[target];
        let source_node_id = node_id_for_node(source_node, &mut ctx);
        let target_node_id = node_id_for_node(target_node, &mut ctx);
        if source_node_id.is_empty() || target_node_id.is_empty() {
            continue;
        }

        let (edge_type, items) = match &graph.graph[edge_idx] {
            GraphEdgeKind::Contains => ("contains", None),
            GraphEdgeKind::Imports => ("imports", None),
            GraphEdgeKind::ImportsFrom { items } => ("imports_from", Some(items.clone())),
            GraphEdgeKind::Calls => ("calls", None),
            GraphEdgeKind::Inherits => ("inherits", None),
            GraphEdgeKind::UsesLibrary => ("uses_library", None),
            GraphEdgeKind::FastApiAppOwnsRoute => ("fastapi_app_owns_route", None),
            GraphEdgeKind::FastApiAppHasMiddleware => ("fastapi_app_has_middleware", None),
            GraphEdgeKind::DependencyInjection => ("dependency_injection", None),
            GraphEdgeKind::FastApiAppLifespan => ("fastapi_app_lifespan", None),
            GraphEdgeKind::MonitoredBy => ("monitored_by", None),
        };

        push_frame(
            &mut raw,
            &EdgeRecord {
                record_type: "edge",
                source_node_id,
                target_node_id,
                edge_type,
                items,
            },
        )?;
    }

    // edges_done control record
    push_frame(
        &mut raw,
        &ControlRecord {
            record_type: "control",
            event: "edges_done",
        },
    )?;

    Ok(zstd::stream::encode_all(std::io::Cursor::new(raw), 3)?)
}

/// Encode a chunk of graph edges into the wire format.
///
/// # Arguments
///
/// * `graph` - The code graph containing edges to encode
/// * `ctx` - ID context for computing stable node identifiers
/// * `start` - Starting index in the edge list
/// * `max_records` - Maximum number of records to include in this chunk
/// * `seq` - Sequence number for this chunk
///
/// # Returns
///
/// Zstd-compressed bytes containing the framed msgpack records.
pub fn encode_edges_chunk(
    graph: &CodeGraph,
    ctx: &mut IdContext,
    start: usize,
    max_records: usize,
    seq: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(1024 * 1024);
    let mut hasher = Xxh3::new();

    let edge_indices: Vec<_> = graph.graph.edge_indices().collect();
    let end = (start + max_records).min(edge_indices.len());

    let mut edges = 0u32;

    for edge_idx in &edge_indices[start..end] {
        let Some((source, target)) = graph.graph.edge_endpoints(*edge_idx) else {
            continue;
        };

        let source_node = &graph.graph[source];
        let target_node = &graph.graph[target];
        let source_node_id = node_id_for_node(source_node, ctx);
        let target_node_id = node_id_for_node(target_node, ctx);
        if source_node_id.is_empty() || target_node_id.is_empty() {
            continue;
        }

        let (edge_type, items) = match &graph.graph[*edge_idx] {
            GraphEdgeKind::Contains => ("contains", None),
            GraphEdgeKind::Imports => ("imports", None),
            GraphEdgeKind::ImportsFrom { items } => ("imports_from", Some(items.clone())),
            GraphEdgeKind::Calls => ("calls", None),
            GraphEdgeKind::Inherits => ("inherits", None),
            GraphEdgeKind::UsesLibrary => ("uses_library", None),
            GraphEdgeKind::FastApiAppOwnsRoute => ("fastapi_app_owns_route", None),
            GraphEdgeKind::FastApiAppHasMiddleware => ("fastapi_app_has_middleware", None),
            GraphEdgeKind::DependencyInjection => ("dependency_injection", None),
            GraphEdgeKind::FastApiAppLifespan => ("fastapi_app_lifespan", None),
            GraphEdgeKind::MonitoredBy => ("monitored_by", None),
        };

        let frame = push_frame(
            &mut raw,
            &EdgeRecord {
                record_type: "edge",
                source_node_id,
                target_node_id,
                edge_type,
                items,
            },
        )?;

        hasher.update(&frame);
        edges += 1;
    }

    let checksum = hasher.digest();

    push_frame(
        &mut raw,
        &ChunkDoneRecord {
            record_type: "control",
            event: "chunk_done",
            phase: "edges",
            seq,
            nodes: 0,
            edges,
            checksum,
        },
    )?;

    Ok(zstd::stream::encode_all(std::io::Cursor::new(raw), 3)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_frames(mut data: &[u8]) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while data.len() >= 4 {
            let len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
            data = &data[4..];
            let payload = &data[..len];
            data = &data[len..];
            let v: serde_json::Value = rmp_serde::from_slice(payload).unwrap();
            out.push(v);
        }
        out
    }

    #[test]
    fn nodes_chunk_has_chunk_done() {
        let mut graph = CodeGraph::new();

        let file_id = FileId(1);
        let _ = graph.graph.add_node(GraphNode::File {
            file_id,
            path: "a.py".to_string(),
            language: unfault_core::types::context::Language::Python,
        });

        let mut ctx = IdContext::new(
            &graph,
            Some("git@github.com:test/repo.git".to_string()),
            "wks_test123".to_string(),
        );

        let body = encode_nodes_chunk(&graph, &mut ctx, 0, 10, 0).unwrap();
        let decoded = zstd::stream::decode_all(std::io::Cursor::new(body)).unwrap();
        let frames = decode_frames(&decoded);
        assert!(frames.iter().any(|v| v["event"] == "chunk_done"));
    }

    #[test]
    fn node_ids_use_stable_format() {
        let mut graph = CodeGraph::new();

        let file_id = FileId(1);
        let _ = graph.graph.add_node(GraphNode::File {
            file_id,
            path: "src/main.py".to_string(),
            language: unfault_core::types::context::Language::Python,
        });
        let _ = graph.graph.add_node(GraphNode::Function {
            file_id,
            name: "process".to_string(),
            qualified_name: "MyClass.process".to_string(),
            is_async: false,
            is_handler: false,
            http_method: None,
            http_path: None,
        });

        let mut ctx = IdContext::new(
            &graph,
            Some("git@github.com:acme/payments.git".to_string()),
            "wks_ignored".to_string(),
        );

        let body = encode_nodes_chunk(&graph, &mut ctx, 0, 10, 0).unwrap();
        let decoded = zstd::stream::decode_all(std::io::Cursor::new(body)).unwrap();
        let frames = decode_frames(&decoded);

        // Find node records (not control records)
        let node_frames: Vec<_> = frames.iter().filter(|f| f["type"] == "node").collect();

        assert_eq!(node_frames.len(), 2);

        // File node should have uf:file:v1: prefix
        let file_node = node_frames
            .iter()
            .find(|f| f["node_type"] == "file")
            .unwrap();
        let file_node_id = file_node["node_id"].as_str().unwrap();
        assert!(
            file_node_id.starts_with("uf:file:v1:"),
            "File node_id should start with uf:file:v1:, got: {}",
            file_node_id
        );
        assert_eq!(file_node_id.len(), 11 + 24); // prefix + 24 hex chars

        // Function node should have uf:sym:v1: prefix
        let func_node = node_frames
            .iter()
            .find(|f| f["node_type"] == "function")
            .unwrap();
        let func_node_id = func_node["node_id"].as_str().unwrap();
        assert!(
            func_node_id.starts_with("uf:sym:v1:"),
            "Function node_id should start with uf:sym:v1:, got: {}",
            func_node_id
        );
        assert_eq!(func_node_id.len(), 10 + 24); // prefix + 24 hex chars
    }

    #[test]
    fn same_file_same_id_different_git_formats() {
        // Test that the same file produces the same ID regardless of git URL format
        let mut graph = CodeGraph::new();
        let file_id = FileId(1);
        let _ = graph.graph.add_node(GraphNode::File {
            file_id,
            path: "src/main.py".to_string(),
            language: unfault_core::types::context::Language::Python,
        });

        let git_formats = [
            "git@github.com:acme/repo.git",
            "https://github.com/acme/repo.git",
            "ssh://git@github.com/acme/repo.git",
        ];

        let mut ids = Vec::new();
        for git_remote in git_formats {
            let mut ctx = IdContext::new(&graph, Some(git_remote.to_string()), "wks_x".to_string());

            let body = encode_nodes_chunk(&graph, &mut ctx, 0, 10, 0).unwrap();
            let decoded = zstd::stream::decode_all(std::io::Cursor::new(body)).unwrap();
            let frames = decode_frames(&decoded);

            let file_node = frames.iter().find(|f| f["node_type"] == "file").unwrap();
            ids.push(file_node["node_id"].as_str().unwrap().to_string());
        }

        // All IDs should be identical
        assert_eq!(
            ids[0], ids[1],
            "SSH and HTTPS formats should produce same ID"
        );
        assert_eq!(
            ids[1], ids[2],
            "HTTPS and ssh:// formats should produce same ID"
        );
    }
}

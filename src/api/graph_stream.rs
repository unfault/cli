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

use std::collections::HashMap;

use serde::Serialize;
use unfault_core::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use unfault_core::parse::ast::FileId;
use xxhash_rust::xxh3::Xxh3;

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

fn node_id_for_node(node: &GraphNode, file_id_to_path: &HashMap<FileId, String>) -> String {
    match node {
        GraphNode::File { path, .. } => path.clone(),
        GraphNode::ExternalModule { name, .. } => format!("ext:{name}"),
        GraphNode::Function {
            file_id,
            qualified_name,
            name,
            ..
        } => {
            let file_path = file_id_to_path.get(file_id).cloned().unwrap_or_default();
            let func_name = if qualified_name.is_empty() {
                name.as_str()
            } else {
                qualified_name.as_str()
            };
            if file_path.is_empty() {
                func_name.to_string()
            } else {
                format!("{file_path}:{func_name}")
            }
        }
        GraphNode::Class { file_id, name } => {
            let file_path = file_id_to_path.get(file_id).cloned().unwrap_or_default();
            if file_path.is_empty() {
                name.clone()
            } else {
                format!("{file_path}:{name}")
            }
        }
        GraphNode::FastApiApp { .. }
        | GraphNode::FastApiRoute { .. }
        | GraphNode::FastApiMiddleware { .. } => {
            // Not currently persisted.
            "".to_string()
        }
    }
}

fn build_file_id_map(graph: &CodeGraph) -> HashMap<FileId, String> {
    let mut map = HashMap::new();
    for node_idx in graph.graph.node_indices() {
        if let GraphNode::File { file_id, path, .. } = &graph.graph[node_idx] {
            map.insert(*file_id, path.clone());
        }
    }
    map
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

pub fn encode_nodes_chunk(
    graph: &CodeGraph,
    start: usize,
    max_records: usize,
    seq: u32,
) -> anyhow::Result<Vec<u8>> {
    let file_id_to_path = build_file_id_map(graph);
    let mut raw = Vec::with_capacity(1024 * 1024);
    let mut hasher = Xxh3::new();

    let node_indices: Vec<_> = graph.graph.node_indices().collect();
    let end = (start + max_records).min(node_indices.len());

    let mut nodes = 0u32;

    for idx in &node_indices[start..end] {
        let node = &graph.graph[*idx];
        let node_id = node_id_for_node(node, &file_id_to_path);
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
                let file_path = file_id_to_path.get(file_id).cloned();
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
                    },
                )?
            }
            GraphNode::Class { file_id, name } => {
                let file_path = file_id_to_path.get(file_id).cloned();
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
                    },
                )?
            }
            GraphNode::FastApiApp { .. }
            | GraphNode::FastApiRoute { .. }
            | GraphNode::FastApiMiddleware { .. } => continue,
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

pub fn encode_edges_chunk(
    graph: &CodeGraph,
    start: usize,
    max_records: usize,
    seq: u32,
) -> anyhow::Result<Vec<u8>> {
    let file_id_to_path = build_file_id_map(graph);
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
        let source_node_id = node_id_for_node(source_node, &file_id_to_path);
        let target_node_id = node_id_for_node(target_node, &file_id_to_path);
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

        let body = encode_nodes_chunk(&graph, 0, 10, 0).unwrap();
        let decoded = zstd::stream::decode_all(std::io::Cursor::new(body)).unwrap();
        let frames = decode_frames(&decoded);
        assert!(frames.iter().any(|v| v["event"] == "chunk_done"));
    }
}

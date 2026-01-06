//! Streaming graph encoding for `/api/v1/graph/ingest`.
//!
//! The wire format is a framed msgpack stream:
//! - Each record is encoded as msgpack
//! - Each msgpack payload is prefixed by a 4-byte big-endian length
//! - The byte stream is zstd-compressed in chunks

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::Stream;
use futures_util::stream;
use serde::Serialize;
use unfault_core::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use unfault_core::parse::ast::FileId;
use petgraph::graph::{EdgeIndex, NodeIndex};

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
struct ControlRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    event: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Nodes,
    NodesDone,
    Edges,
    EdgesDone,
    Done,
}

struct StreamState {
    graph: Arc<CodeGraph>,
    node_indices: Vec<NodeIndex>,
    edge_indices: Vec<EdgeIndex>,
    node_pos: usize,
    edge_pos: usize,
    phase: Phase,
    file_id_to_path: HashMap<FileId, String>,
    raw_buf: Vec<u8>,
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
        GraphNode::FastApiApp { file_id, var_name } => {
            let file_path = file_id_to_path.get(file_id).cloned().unwrap_or_default();
            if file_path.is_empty() {
                format!("fastapi_app:{var_name}")
            } else {
                format!("{file_path}:fastapi_app:{var_name}")
            }
        }
        GraphNode::FastApiRoute {
            file_id,
            http_method,
            path,
        } => {
            let file_path = file_id_to_path.get(file_id).cloned().unwrap_or_default();
            if file_path.is_empty() {
                format!("fastapi_route:{http_method}:{path}")
            } else {
                format!("{file_path}:fastapi_route:{http_method}:{path}")
            }
        }
        GraphNode::FastApiMiddleware {
            file_id,
            app_var_name,
            middleware_type,
        } => {
            let file_path = file_id_to_path.get(file_id).cloned().unwrap_or_default();
            if file_path.is_empty() {
                format!("fastapi_middleware:{app_var_name}:{middleware_type}")
            } else {
                format!("{file_path}:fastapi_middleware:{app_var_name}:{middleware_type}")
            }
        }
    }
}

fn push_frame(buf: &mut Vec<u8>, value: &impl Serialize) -> anyhow::Result<()> {
    let payload = rmp_serde::to_vec_named(value)?;
    let len = u32::try_from(payload.len())?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(())
}

fn flush_compressed(raw: &mut Vec<u8>) -> Option<anyhow::Result<Bytes>> {
    if raw.is_empty() {
        return None;
    }

    let to_compress = std::mem::take(raw);
    Some(
        zstd::stream::encode_all(Cursor::new(to_compress), 3)
            .map(Bytes::from)
            .map_err(|e| anyhow::anyhow!(e)),
    )
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

/// Stream a full graph as zstd-compressed framed msgpack.
///
/// This function takes ownership of the graph to satisfy reqwest's `'static`
/// requirement for streaming request bodies.
pub fn stream_graph_as_zstd_msgpack(
    graph: CodeGraph,
) -> impl Stream<Item = Result<Bytes, anyhow::Error>> + Send + 'static {
    let graph = Arc::new(graph);

    let state = StreamState {
        node_indices: graph.graph.node_indices().collect(),
        edge_indices: graph.graph.edge_indices().collect(),
        node_pos: 0,
        edge_pos: 0,
        phase: Phase::Nodes,
        file_id_to_path: build_file_id_map(&graph),
        raw_buf: Vec::with_capacity(256 * 1024),
        graph,
    };

    const RAW_TARGET: usize = 256 * 1024;

    stream::unfold(state, move |mut st| async move {
        loop {
            if st.raw_buf.len() >= RAW_TARGET {
                return flush_compressed(&mut st.raw_buf).map(|res| (res, st));
            }

            match st.phase {
                Phase::Nodes => {
                    if st.node_pos >= st.node_indices.len() {
                        st.phase = Phase::NodesDone;
                        continue;
                    }

                    let idx = st.node_indices[st.node_pos];
                    st.node_pos += 1;

                    let node = &st.graph.graph[idx];
                    match node {
                        GraphNode::File { path, language, .. } => {
                            let rec = NodeRecord {
                                record_type: "node",
                                node_id: node_id_for_node(node, &st.file_id_to_path),
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
                            };
                            if let Err(e) = push_frame(&mut st.raw_buf, &rec) {
                                return Some((Err(e), st));
                            }
                        }
                        GraphNode::ExternalModule { name, category } => {
                            let rec = NodeRecord {
                                record_type: "node",
                                node_id: node_id_for_node(node, &st.file_id_to_path),
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
                            };
                            if let Err(e) = push_frame(&mut st.raw_buf, &rec) {
                                return Some((Err(e), st));
                            }
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
                            let file_path = st.file_id_to_path.get(file_id).cloned();
                            let rec = NodeRecord {
                                record_type: "node",
                                node_id: node_id_for_node(node, &st.file_id_to_path),
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
                            };
                            if let Err(e) = push_frame(&mut st.raw_buf, &rec) {
                                return Some((Err(e), st));
                            }
                        }
                        GraphNode::Class { file_id, name } => {
                            let file_path = st.file_id_to_path.get(file_id).cloned();
                            let rec = NodeRecord {
                                record_type: "node",
                                node_id: node_id_for_node(node, &st.file_id_to_path),
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
                            };
                            if let Err(e) = push_frame(&mut st.raw_buf, &rec) {
                                return Some((Err(e), st));
                            }
                        }
                        GraphNode::FastApiApp { .. } => {
                            // Not currently persisted as a first-class node in the DB.
                        }
                        GraphNode::FastApiRoute { .. } => {
                            // Not currently persisted as a first-class node in the DB.
                        }
                        GraphNode::FastApiMiddleware { .. } => {
                            // Not currently persisted as a first-class node in the DB.
                        }
                    }
                }
                Phase::NodesDone => {
                    let rec = ControlRecord {
                        record_type: "control",
                        event: "nodes_done",
                    };
                    if let Err(e) = push_frame(&mut st.raw_buf, &rec) {
                        return Some((Err(e), st));
                    }
                    st.phase = Phase::Edges;
                }
                Phase::Edges => {
                    if st.edge_pos >= st.edge_indices.len() {
                        st.phase = Phase::EdgesDone;
                        continue;
                    }

                    let edge_idx = st.edge_indices[st.edge_pos];
                    st.edge_pos += 1;

                    let (source, target) = match st.graph.graph.edge_endpoints(edge_idx) {
                        Some(v) => v,
                        None => continue,
                    };

                    let source_node = &st.graph.graph[source];
                    let target_node = &st.graph.graph[target];
                    let source_node_id = node_id_for_node(source_node, &st.file_id_to_path);
                    let target_node_id = node_id_for_node(target_node, &st.file_id_to_path);

                    let (edge_type, items) = match &st.graph.graph[edge_idx] {
                        GraphEdgeKind::Contains => ("contains", None),
                        GraphEdgeKind::Imports => ("imports", None),
                        GraphEdgeKind::ImportsFrom { items } => {
                            ("imports_from", Some(items.clone()))
                        }
                        GraphEdgeKind::Calls => ("calls", None),
                        GraphEdgeKind::Inherits => ("inherits", None),
                        GraphEdgeKind::UsesLibrary => ("uses_library", None),
                        GraphEdgeKind::FastApiAppOwnsRoute => ("fastapi_app_owns_route", None),
                        GraphEdgeKind::FastApiAppHasMiddleware => {
                            ("fastapi_app_has_middleware", None)
                        }
                    };

                    let rec = EdgeRecord {
                        record_type: "edge",
                        source_node_id,
                        target_node_id,
                        edge_type,
                        items,
                    };

                    if let Err(e) = push_frame(&mut st.raw_buf, &rec) {
                        return Some((Err(e), st));
                    }
                }
                Phase::EdgesDone => {
                    let rec = ControlRecord {
                        record_type: "control",
                        event: "edges_done",
                    };
                    if let Err(e) = push_frame(&mut st.raw_buf, &rec) {
                        return Some((Err(e), st));
                    }
                    st.phase = Phase::Done;
                }
                Phase::Done => {
                    return flush_compressed(&mut st.raw_buf).map(|res| (res, st));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures_util::StreamExt;

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

    #[tokio::test]
    async fn stream_emits_nodes_control_edges() {
        let mut graph = CodeGraph::new();

        let file_id = FileId(1);
        let file_idx = graph.graph.add_node(GraphNode::File {
            file_id,
            path: "a.py".to_string(),
            language: unfault_core::types::context::Language::Python,
        });
        let ext_idx = graph.graph.add_node(GraphNode::ExternalModule {
            name: "requests".to_string(),
            category: unfault_core::graph::ModuleCategory::HttpClient,
        });

        graph
            .graph
            .add_edge(file_idx, ext_idx, GraphEdgeKind::UsesLibrary);

        let mut chunks = Vec::new();
        let mut stream = Box::pin(stream_graph_as_zstd_msgpack(graph));
        while let Some(item) = stream.next().await {
            chunks.push(item.unwrap());
        }

        let mut decompressed = Vec::new();
        for chunk in chunks {
            let decoded = zstd::stream::decode_all(Cursor::new(chunk)).unwrap();
            decompressed.extend_from_slice(&decoded);
        }

        let frames = decode_frames(&decompressed);
        assert!(frames.iter().any(|v| v["type"] == "control" && v["event"] == "nodes_done"));
        assert!(frames.iter().any(|v| v["type"] == "control" && v["event"] == "edges_done"));
        assert!(frames.iter().any(|v| v["type"] == "edge" && v["edge_type"] == "uses_library"));
    }
}

//! Fault scenario generation helpers for local testing.
//!
//! This command generates `fault` scenario YAML files from discovered HTTP routes.
//! It is intentionally local-only (no API calls) and is designed for LLM agents
//! to turn "operational healthiness" guidance into runnable artifacts.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::fault_scenarios::{
    find_available_file_path, get_or_create_scenario_dir, render_route_scenario_suite,
    ScenarioSuiteConfig,
};
use crate::session::{build_ir_cached, WorkspaceScanner};

#[derive(Debug, Clone)]
pub struct GenerateFaultScenariosArgs {
    pub workspace: Option<String>,
    pub proxy_port: u16,
    pub remote: String,
    pub limit: usize,
    pub only_outbound: bool,
    pub write: bool,
    pub json: bool,
    pub include_yaml: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteSummary {
    method: String,
    path: String,
    file: String,
    handler: String,
    outbound_calls: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedFileSummary {
    route: RouteSummary,
    file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    yaml: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateFaultScenariosOutput {
    workspace_root: String,
    routes_total: usize,
    routes_selected: usize,
    files_written: usize,
    scenario_dir: String,
    generated: Vec<GeneratedFileSummary>,
}

#[derive(Debug, Clone)]
struct DiscoveredRoute {
    method: String,
    path: String,
    file: String,
    handler: String,
    outbound_calls: bool,
}

fn discover_routes(workspace_root: &Path, include_tests: bool) -> Result<Vec<DiscoveredRoute>> {
    use petgraph::visit::EdgeRef;
    use unfault_core::graph::{GraphEdgeKind, GraphNode, ModuleCategory};
    use unfault_core::parse::ast::FileId;

    fn is_test_path(path: &str) -> bool {
        let lower = path.to_lowercase().replace('\\', "/");
        lower.starts_with("test/")
            || lower.starts_with("tests/")
            || lower.starts_with("testdata/")
            || lower.starts_with("fixtures/")
            || lower.contains("/test/")
            || lower.contains("/tests/")
            || lower.contains("/testdata/")
            || lower.contains("/fixtures/")
            || lower.contains("/__tests__/")
            || lower.ends_with("_test.go")
            || lower.ends_with(".spec.ts")
            || lower.ends_with(".spec.tsx")
            || lower.ends_with(".test.ts")
            || lower.ends_with(".test.tsx")
            || lower.ends_with(".spec.js")
            || lower.ends_with(".spec.jsx")
            || lower.ends_with(".test.js")
            || lower.ends_with(".test.jsx")
    }

    let mut scanner = WorkspaceScanner::new(workspace_root);
    let workspace_info = scanner.scan().context("Failed to scan workspace")?;

    let file_paths: Option<Vec<PathBuf>> = if include_tests {
        None
    } else {
        Some(
            workspace_info
                .source_files
                .iter()
                .filter_map(|(p, _)| {
                    let rel = p
                        .strip_prefix(workspace_root)
                        .unwrap_or(p)
                        .to_string_lossy()
                        .to_string();
                    if is_test_path(&rel) {
                        None
                    } else {
                        Some(p.clone())
                    }
                })
                .collect(),
        )
    };

    let build_result = build_ir_cached(workspace_root, file_paths.as_deref(), false, None)
        .context("Failed to parse source files")?;
    let graph = build_result.ir.graph;

    // Build FileId -> path mapping
    let mut file_paths: std::collections::HashMap<FileId, String> =
        std::collections::HashMap::new();
    for idx in graph.file_nodes.values() {
        if let Some(GraphNode::File { file_id, path, .. }) = graph.graph.node_weight(*idx) {
            file_paths.insert(*file_id, path.clone());
        }
    }

    fn is_outbound_category(category: &ModuleCategory) -> bool {
        matches!(
            category,
            ModuleCategory::HttpClient | ModuleCategory::Database
        )
    }

    let outbound_calls_for_file = |file_id: FileId| -> bool {
        let Some(file_idx) = graph.file_nodes.get(&file_id) else {
            return false;
        };
        for edge in graph.graph.edges(*file_idx) {
            if !matches!(edge.weight(), GraphEdgeKind::UsesLibrary) {
                continue;
            }
            if let Some(GraphNode::ExternalModule { category, .. }) =
                graph.graph.node_weight(edge.target())
            {
                if is_outbound_category(category) {
                    return true;
                }
            }
        }
        false
    };

    let mut seen = std::collections::HashSet::new();
    let mut routes: Vec<DiscoveredRoute> = Vec::new();

    for idx in graph.function_nodes.values() {
        let Some(node) = graph.graph.node_weight(*idx) else {
            continue;
        };

        let (method, path, file_id, handler) = match node {
            GraphNode::Function {
                file_id,
                http_method: Some(method),
                http_path: Some(path),
                qualified_name,
                ..
            } => (
                method.clone(),
                path.clone(),
                *file_id,
                qualified_name.clone(),
            ),
            _ => continue,
        };

        let file = file_paths.get(&file_id).cloned().unwrap_or_default();
        if !seen.insert((method.clone(), path.clone(), file.clone())) {
            continue;
        }

        let outbound_calls = outbound_calls_for_file(file_id);

        routes.push(DiscoveredRoute {
            method,
            path,
            file,
            handler,
            outbound_calls,
        });
    }

    routes.sort_by(|a, b| {
        a.method
            .cmp(&b.method)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.file.cmp(&b.file))
    });

    Ok(routes)
}

pub fn execute_generate(args: GenerateFaultScenariosArgs) -> Result<i32> {
    use crate::exit_codes::EXIT_SUCCESS;

    let workspace_root = match args.workspace {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir().context("Failed to get current directory")?,
    };

    let routes = discover_routes(&workspace_root, false)?;
    let routes_total = routes.len();

    let mut selected: Vec<DiscoveredRoute> = if args.only_outbound {
        routes.into_iter().filter(|r| r.outbound_calls).collect()
    } else {
        routes
    };

    selected.truncate(args.limit.max(1));
    let routes_selected = selected.len();

    let scenario_dir = get_or_create_scenario_dir(&workspace_root)
        .context("Failed to get/create scenario directory")?;

    let cfg = ScenarioSuiteConfig {
        local_port: args.proxy_port,
        remote: args.remote.clone(),
    };

    let mut generated: Vec<GeneratedFileSummary> = Vec::new();
    let mut files_written = 0usize;

    for route in selected {
        let out = render_route_scenario_suite(&cfg, &route.method, &route.path);
        let file_path = find_available_file_path(&scenario_dir, &out.file_name);

        if args.write {
            std::fs::write(&file_path, &out.yaml)
                .with_context(|| format!("Failed to write {}", file_path.display()))?;
            files_written += 1;
        }

        let yaml = if args.include_yaml {
            Some(out.yaml)
        } else {
            None
        };
        generated.push(GeneratedFileSummary {
            route: RouteSummary {
                method: route.method,
                path: route.path,
                file: route.file,
                handler: route.handler,
                outbound_calls: route.outbound_calls,
            },
            file_path: file_path
                .strip_prefix(&workspace_root)
                .unwrap_or(&file_path)
                .to_string_lossy()
                .to_string(),
            yaml,
        });
    }

    let output = GenerateFaultScenariosOutput {
        workspace_root: workspace_root.to_string_lossy().to_string(),
        routes_total,
        routes_selected,
        files_written,
        scenario_dir: scenario_dir
            .strip_prefix(&workspace_root)
            .unwrap_or(&scenario_dir)
            .to_string_lossy()
            .to_string(),
        generated,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if args.write {
            println!(
                "Generated {} scenario file(s) in {}",
                files_written, output.scenario_dir
            );
        } else {
            println!(
                "Would generate {} scenario file(s) in {} (use --write)",
                routes_selected, output.scenario_dir
            );
        }
        for item in &output.generated {
            println!(
                "- {} {} -> {}",
                item.route.method, item.route.path, item.file_path
            );
        }
    }

    Ok(EXIT_SUCCESS)
}

//! Fault scenario generation utilities.
//!
//! This module is used by the LSP today and can be reused by the CLI later.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ScenarioSuiteConfig {
    pub local_port: u16,
    pub remote: String,
}

#[derive(Debug, Clone)]
pub struct GeneratedScenarioFile {
    pub file_name: String,
    pub yaml: String,
}

pub fn render_route_scenario_suite(
    config: &ScenarioSuiteConfig,
    method: &str,
    route_path: &str,
) -> GeneratedScenarioFile {
    let method = method.trim().to_uppercase();
    let route_path = normalize_route_path(route_path);

    let call_url = format!("http://127.0.0.1:{}{}", config.local_port, route_path);

    let route_label = format!("{} {}", method, route_path);
    let yaml = render_suite_yaml(config, &method, &call_url, &route_label);

    let file_name = format!(
        "{}.yaml",
        sanitize_filename_component(&format!("{}-{}", method, route_path))
    );

    GeneratedScenarioFile { file_name, yaml }
}

pub fn get_or_create_scenario_dir(workspace_root: &Path) -> std::io::Result<PathBuf> {
    let tests_dir = workspace_root.join("tests").join("fault");
    if tests_dir.exists() {
        return Ok(tests_dir);
    }

    let test_dir = workspace_root.join("test").join("fault");
    if test_dir.exists() {
        return Ok(test_dir);
    }

    fs::create_dir_all(&tests_dir)?;
    Ok(tests_dir)
}

pub fn find_available_file_path(dir: &Path, file_name: &str) -> PathBuf {
    let mut candidate = dir.join(file_name);
    if !candidate.exists() {
        return candidate;
    }

    let ext = candidate
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("yaml")
        .to_string();
    let stem = candidate
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("scenario")
        .to_string();

    for i in 2..1000 {
        candidate = dir.join(format!("{}-{}.{}", stem, i, ext));
        if !candidate.exists() {
            return candidate;
        }
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    dir.join(format!("{}-{}.{}", stem, ts, ext))
}

fn render_suite_yaml(
    config: &ScenarioSuiteConfig,
    method: &str,
    call_url: &str,
    route_label: &str,
) -> String {
    // Note: we intentionally omit any SLO inference here for now.
    let default_slos = [
        ("latency", "P95 < 300ms", "95.0", "300.0"),
        ("error", "P99 < 1% errors", "99.0", "1.0"),
    ];

    let q = |v: &str| format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""));

    let proxy_block = format!(
        "    proxy:\n      disable_http_proxies: true\n      proxies:\n        - \"{}={}\"\n",
        config.local_port, config.remote
    );

    let mut docs: Vec<(String, String, Vec<String>, Vec<String>, bool)> = Vec::new();

    // Periodic pulses under load (matches the kind of example you shared)
    docs.push((
        format!(
            "Periodic 150-250 ms latency pulses during load ({})",
            route_label
        ),
        "Three latency bursts at 10-40-70% of a 10s window; good for P95 drift tracking."
            .to_string(),
        vec![
            "    faults:".to_string(),
            "      - type: latency".to_string(),
            "        mean: 150.0".to_string(),
            "        period: start:10%,duration:15%".to_string(),
            "        direction: egress".to_string(),
            "        side: client".to_string(),
            "      - type: latency".to_string(),
            "        mean: 250.0".to_string(),
            "        period: start:40%,duration:15%".to_string(),
            "        direction: egress".to_string(),
            "        side: client".to_string(),
            "      - type: latency".to_string(),
            "        mean: 150.0".to_string(),
            "        period: start:70%,duration:15%".to_string(),
            "        direction: egress".to_string(),
            "        side: client".to_string(),
        ],
        vec![
            "    strategy:".to_string(),
            "      mode: load".to_string(),
            "      duration: 10s".to_string(),
            "      clients: 3".to_string(),
            "      rps: 2".to_string(),
        ],
        true,
    ));

    // High jitter
    docs.push((
        format!("High jitter (+/-80ms @ 8Hz) ({})", route_label),
        "Emulates bursty uplink; measures buffering robustness.".to_string(),
        vec![
            "    faults:".to_string(),
            "      - type: jitter".to_string(),
            "        amplitude: 80.0".to_string(),
            "        frequency: 8.0".to_string(),
            "        direction: ingress".to_string(),
            "        side: server".to_string(),
        ],
        vec!["    strategy: null".to_string()],
        false,
    ));

    // Bandwidth under load
    docs.push((
        format!("Bandwidth cap (64 KBps) under load ({})", route_label),
        "Models throttled link; validates handling of large payloads.".to_string(),
        vec![
            "    faults:".to_string(),
            "      - type: bandwidth".to_string(),
            "        rate: 64".to_string(),
            "        unit: KBps".to_string(),
            "        direction: ingress".to_string(),
            "        side: server".to_string(),
        ],
        vec![
            "    strategy:".to_string(),
            "      mode: load".to_string(),
            "      duration: 15s".to_string(),
            "      clients: 2".to_string(),
            "      rps: 1".to_string(),
        ],
        true,
    ));

    // Packet loss burst
    docs.push((
        format!("5% packet loss for 4s ({})", route_label),
        "Simulates flaky Wi-Fi or cellular interference.".to_string(),
        vec![
            "    faults:".to_string(),
            "      - type: packetloss".to_string(),
            "        direction: egress".to_string(),
            "        period: start:30%,duration:40%".to_string(),
        ],
        vec!["    strategy: null".to_string()],
        false,
    ));

    // Blackhole window under load
    docs.push((
        format!("Full black-hole for 1s ({})", route_label),
        "Hard outage window; validates timeouts and recovery.".to_string(),
        vec![
            "    faults:".to_string(),
            "      - type: blackhole".to_string(),
            "        direction: both".to_string(),
            "        period: start:45%,duration:10%".to_string(),
        ],
        vec![
            "    strategy:".to_string(),
            "      mode: load".to_string(),
            "      duration: 10s".to_string(),
            "      clients: 2".to_string(),
            "      rps: 3".to_string(),
        ],
        true,
    ));

    let mut out: Vec<String> = Vec::new();
    for (i, (title, description, faults, strategy, include_slo)) in docs.into_iter().enumerate() {
        if i > 0 {
            out.push("---".to_string());
        }
        out.push(format!("title: {}", q(&title)));
        out.push(format!("description: {}", q(&description)));
        out.push("items:".to_string());
        out.push("- call:".to_string());
        out.push(format!("    method: {}", method));
        out.push(format!("    url: {}", call_url));
        if method == "POST" || method == "PUT" || method == "PATCH" {
            out.push("    headers:".to_string());
            out.push("      content-type: application/json".to_string());
            out.push(format!("    body: {}", q("{}")));
        }
        out.push("  context:".to_string());
        out.push("    upstreams: []".to_string());
        out.extend(proxy_block.lines().map(|l| l.to_string()));
        out.extend(faults);
        out.extend(strategy);
        if include_slo {
            out.push("    slo:".to_string());
            for (t, title, objective, threshold) in default_slos {
                out.push(format!("      - slo_type: {}", t));
                out.push(format!("        title: {}", q(title)));
                out.push(format!("        objective: {}", objective));
                out.push(format!("        threshold: {}", threshold));
            }
        }
        out.push("  expect:".to_string());
        if include_slo {
            out.push("    all_slo_are_valid: true".to_string());
        } else {
            out.push("    status: 200".to_string());
        }
    }

    format!("{}\n", out.join("\n"))
}

fn normalize_route_path(path: &str) -> String {
    let p = path.trim();
    if p.is_empty() {
        return "/".to_string();
    }
    if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{}", p)
    }
}

fn sanitize_filename_component(value: &str) -> String {
    let v = value.trim().to_ascii_lowercase().replace('/', "-");
    let mut out = String::new();
    let mut prev_dash = false;
    for c in v.chars() {
        let is_ok = c.is_ascii_alphanumeric();
        if is_ok {
            out.push(c);
            prev_dash = false;
            continue;
        }
        if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_render_route_suite_is_multi_doc() {
        let cfg = ScenarioSuiteConfig {
            local_port: 9090,
            remote: "http://127.0.0.1:8000".to_string(),
        };
        let out = render_route_scenario_suite(&cfg, "post", "/payments");
        assert!(out.yaml.contains("---"));
        assert!(out.yaml.contains("proxies:"));
        assert!(out.file_name.contains("post-payments"));
    }

    #[test]
    fn test_scenario_dir_prefers_existing() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let test_fault = root.join("test").join("fault");
        fs::create_dir_all(&test_fault).unwrap();
        let dir = get_or_create_scenario_dir(root).unwrap();
        assert_eq!(dir, test_fault);

        let tests_fault = root.join("tests").join("fault");
        fs::create_dir_all(&tests_fault).unwrap();
        let dir = get_or_create_scenario_dir(root).unwrap();
        assert_eq!(dir, tests_fault);
    }
}

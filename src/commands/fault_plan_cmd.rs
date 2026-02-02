//! Fault planning helpers for humans and agents.
//!
//! This command intentionally supports a small, curated subset of fault scenarios.
//! It generates a concrete `fault run ...` command so users can copy/paste it.

use anyhow::{anyhow, bail, Result};

#[derive(Debug, Clone)]
pub struct FaultPlanArgs {
    pub scenario: String,
    pub target: String,
    pub proxy_port: u16,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum RecipeKind {
    Latency,
    Jitter,
    Bandwidth,
    Blackhole,
    PacketLoss,
    HttpResponse,
}

#[derive(Debug, Clone)]
struct ParsedRecipe {
    kind: RecipeKind,
    duration: String,
    // latency
    latency_ms: Option<u32>,
    // jitter
    jitter_amplitude_ms: Option<f32>,
    jitter_frequency_hz: Option<f32>,
    // bandwidth
    bandwidth_rate: Option<u32>,
    bandwidth_unit: Option<String>,
    // packet loss (currently no rate flag exposed in run options)
    packet_loss_percent: Option<f32>,
    // http response
    http_status: Option<u16>,
    http_probability: Option<f32>,
}

fn normalize_scenario(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '%' || ch == '/' || ch == ':' {
            out.push(ch);
        } else if ch.is_whitespace() || ch == '-' || ch == '_' || ch == '=' || ch == '@' {
            out.push(' ');
        }
        // drop other punctuation
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_duration_token(tok: &str) -> Option<String> {
    // Keep it intentionally simple: accept values `fault` will accept anyway.
    // Examples: 250ms, 30s, 2m, 1h.
    let t = tok.trim();
    if t.is_empty() {
        return None;
    }
    let (num, unit) = t.chars().partition::<String, _>(|c| c.is_ascii_digit());
    if num.is_empty() {
        return None;
    }
    let unit = unit.as_str();
    match unit {
        "ms" | "s" | "m" | "h" => Some(format!("{}{}", num, unit)),
        _ => None,
    }
}

fn parse_ms(tok: &str) -> Option<u32> {
    let t = tok.trim().to_ascii_lowercase();
    if let Some(stripped) = t.strip_suffix("ms") {
        return stripped.parse::<u32>().ok();
    }
    // Allow bare numbers as milliseconds.
    t.parse::<u32>().ok()
}

fn parse_percent(tok: &str) -> Option<f32> {
    let t = tok.trim();
    let v = t.strip_suffix('%').unwrap_or(t);
    let f = v.parse::<f32>().ok()?;
    if !(0.0..=100.0).contains(&f) {
        return None;
    }
    Some(f)
}

fn parse_hz(tok: &str) -> Option<f32> {
    let t = tok.trim().to_ascii_lowercase();
    let v = t.strip_suffix("hz").unwrap_or(&t);
    let f = v.parse::<f32>().ok()?;
    if f < 0.0 {
        return None;
    }
    Some(f)
}

fn parse_bandwidth_unit(tok: &str) -> Option<String> {
    let u = tok.trim();
    // Preserve canonical units as expected by fault.
    let up = u.to_ascii_uppercase();
    match up.as_str() {
        "BPS" => Some("Bps".to_string()),
        "KBPS" => Some("KBps".to_string()),
        "MBPS" => Some("MBps".to_string()),
        "GBPS" => Some("GBps".to_string()),
        _ => None,
    }
}

fn parse_recipe(raw: &str) -> Result<ParsedRecipe> {
    let normalized = normalize_scenario(raw);
    let lower = normalized.to_ascii_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.is_empty() {
        bail!("Empty scenario. Try: 'latency 200ms for 30s'");
    }

    let kind = match tokens[0] {
        "latency" => RecipeKind::Latency,
        "jitter" => RecipeKind::Jitter,
        "bandwidth" => RecipeKind::Bandwidth,
        "blackhole" => RecipeKind::Blackhole,
        "drop" | "packetloss" | "packet-loss" | "packet" => RecipeKind::PacketLoss,
        "http" | "http-response" | "httpresponse" | "status" => RecipeKind::HttpResponse,
        other => {
            bail!(
                "Unsupported scenario kind '{}'. Try one of: latency, jitter, bandwidth, drop, blackhole",
                other
            )
        }
    };

    // default duration
    let mut duration = "30s".to_string();
    if let Some(idx) = tokens.iter().position(|t| *t == "for") {
        if let Some(tok) = tokens.get(idx + 1) {
            duration = parse_duration_token(tok)
                .ok_or_else(|| anyhow!("Invalid duration '{}'. Examples: 250ms, 30s, 2m", tok))?;
        } else {
            bail!("Expected duration after 'for'. Example: 'latency 200ms for 30s'");
        }
    }

    let mut out = ParsedRecipe {
        kind,
        duration,
        latency_ms: None,
        jitter_amplitude_ms: None,
        jitter_frequency_hz: None,
        bandwidth_rate: None,
        bandwidth_unit: None,
        packet_loss_percent: None,
        http_status: None,
        http_probability: None,
    };

    match out.kind {
        RecipeKind::Latency => {
            // latency <ms> [for <duration>]
            let ms = tokens.get(1).and_then(|t| parse_ms(t)).ok_or_else(|| {
                anyhow!("Expected latency value after 'latency'. Example: 'latency 200ms for 30s'")
            })?;
            out.latency_ms = Some(ms);
        }
        RecipeKind::Jitter => {
            // jitter <amplitude_ms> [at <hz>] [for <duration>]
            let amp = tokens
                .get(1)
                .and_then(|t| parse_ms(t).map(|v| v as f32))
                .ok_or_else(|| {
                    anyhow!(
                        "Expected jitter amplitude after 'jitter'. Example: 'jitter 80ms for 30s'"
                    )
                })?;
            out.jitter_amplitude_ms = Some(amp);

            // Optional: 'at 8hz' or '8hz'
            if let Some(at_idx) = tokens.iter().position(|t| *t == "at") {
                if let Some(tok) = tokens.get(at_idx + 1) {
                    out.jitter_frequency_hz = Some(parse_hz(tok).ok_or_else(|| {
                        anyhow!(
                            "Invalid jitter frequency '{}'. Example: 'jitter 80ms at 8hz for 30s'",
                            tok
                        )
                    })?);
                }
            } else {
                // Scan for a 'Xhz' token
                for t in &tokens {
                    if t.ends_with("hz") {
                        if let Some(hz) = parse_hz(t) {
                            out.jitter_frequency_hz = Some(hz);
                            break;
                        }
                    }
                }
            }

            // Default frequency
            if out.jitter_frequency_hz.is_none() {
                out.jitter_frequency_hz = Some(5.0);
            }
        }
        RecipeKind::Bandwidth => {
            // bandwidth <rate> <unit> [for <duration>]
            let rate = tokens
                .get(1)
                .and_then(|t| t.parse::<u32>().ok())
                .ok_or_else(|| anyhow!("Expected bandwidth rate after 'bandwidth'. Example: 'bandwidth 512 KBps for 30s'"))?;
            let unit_tok = tokens.get(2).ok_or_else(|| {
                anyhow!("Expected bandwidth unit. Example: 'bandwidth 512 KBps for 30s'")
            })?;
            let unit = parse_bandwidth_unit(unit_tok).ok_or_else(|| {
                anyhow!(
                    "Invalid bandwidth unit '{}'. Use one of: Bps, KBps, MBps, GBps",
                    unit_tok
                )
            })?;
            out.bandwidth_rate = Some(rate);
            out.bandwidth_unit = Some(unit);
        }
        RecipeKind::Blackhole => {
            // blackhole [for <duration>]
        }
        RecipeKind::PacketLoss => {
            // drop <percent> [for <duration>]
            // Note: fault run currently documents no rate knob for packet loss.
            if let Some(p) = tokens.get(1).and_then(|t| parse_percent(t)) {
                out.packet_loss_percent = Some(p);
            }
        }
        RecipeKind::HttpResponse => {
            // http <status> [prob <0-1>] [for <duration>]
            let status = tokens
                .get(1)
                .and_then(|t| t.parse::<u16>().ok())
                .unwrap_or(500);
            out.http_status = Some(status);

            if let Some(idx) = tokens
                .iter()
                .position(|t| *t == "prob" || *t == "probability")
            {
                if let Some(tok) = tokens.get(idx + 1) {
                    let p = tok.parse::<f32>().ok().filter(|v| (0.0..=1.0).contains(v));
                    out.http_probability = p;
                }
            }
        }
    }

    Ok(out)
}

fn shell_quote_double(s: &str) -> String {
    // Minimal double-quote escaping for shell.
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn build_fault_run_command(
    recipe: &ParsedRecipe,
    proxy_port: u16,
    target: &str,
) -> (Vec<String>, String, Vec<String>) {
    let proxy_mapping = format!("{}={}", proxy_port, target);
    let proxy_mapping_q = shell_quote_double(&proxy_mapping);

    let mut argv: Vec<String> = vec![
        "fault".to_string(),
        "run".to_string(),
        "--duration".to_string(),
        recipe.duration.clone(),
        "--proxy".to_string(),
        proxy_mapping.clone(),
    ];
    let mut notes: Vec<String> = Vec::new();

    match recipe.kind {
        RecipeKind::Latency => {
            let ms = recipe.latency_ms.unwrap_or(200);
            argv.extend([
                "--with-latency".to_string(),
                "--latency-distribution".to_string(),
                "uniform".to_string(),
                "--latency-min".to_string(),
                ms.to_string(),
                "--latency-max".to_string(),
                ms.to_string(),
            ]);
        }
        RecipeKind::Jitter => {
            let amp = recipe.jitter_amplitude_ms.unwrap_or(20.0);
            let hz = recipe.jitter_frequency_hz.unwrap_or(5.0);
            argv.extend([
                "--with-jitter".to_string(),
                "--jitter-amplitude".to_string(),
                format!("{:.1}", amp),
                "--jitter-frequency".to_string(),
                format!("{:.1}", hz),
            ]);
        }
        RecipeKind::Bandwidth => {
            let rate = recipe.bandwidth_rate.unwrap_or(1000);
            let unit = recipe
                .bandwidth_unit
                .clone()
                .unwrap_or_else(|| "Bps".to_string());
            argv.extend([
                "--with-bandwidth".to_string(),
                "--bandwidth-rate".to_string(),
                rate.to_string(),
                "--bandwidth-unit".to_string(),
                unit,
            ]);
        }
        RecipeKind::Blackhole => {
            argv.push("--with-blackhole".to_string());
        }
        RecipeKind::PacketLoss => {
            argv.push("--with-packet-loss".to_string());
            if let Some(p) = recipe.packet_loss_percent {
                notes.push(format!(
                    "Note: packet loss percentage ({p}%) is not configurable via 'fault run' options; enabling default packet loss."));
            }
        }
        RecipeKind::HttpResponse => {
            let status = recipe.http_status.unwrap_or(500);
            argv.extend([
                "--with-http-response".to_string(),
                "--http-response-status".to_string(),
                status.to_string(),
            ]);
            if let Some(p) = recipe.http_probability {
                argv.extend([
                    "--http-response-trigger-probability".to_string(),
                    format!("{:.3}", p),
                ]);
            }
        }
    }

    // Build shell string with minimal quoting.
    let mut shell_parts: Vec<String> = Vec::with_capacity(argv.len());
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        if arg == "--proxy" {
            shell_parts.push(arg.clone());
            // next is mapping
            if let Some(mapping) = iter.next() {
                shell_parts.push(proxy_mapping_q.clone());
                // Keep argv already has unquoted mapping.
                // shell uses quoted mapping to preserve scheme separators.
                let _ = mapping;
            }
            continue;
        }
        shell_parts.push(arg.clone());
    }
    let shell = shell_parts.join(" ");

    (argv, shell, notes)
}

pub fn execute_plan(args: FaultPlanArgs) -> Result<i32> {
    use crate::exit_codes::EXIT_SUCCESS;

    let recipe = parse_recipe(&args.scenario)?;
    let (argv, shell, notes) = build_fault_run_command(&recipe, args.proxy_port, &args.target);

    if args.json {
        let out = serde_json::json!({
            "schema_version": "unfault.fault_plan.v1",
            "input": {
                "scenario": args.scenario,
                "target": args.target,
                "proxy_port": args.proxy_port,
            },
            "fault": {
                "argv": argv,
                "shell": shell,
            },
            "notes": notes,
            "examples": {
                "drive_traffic": format!("curl -i http://127.0.0.1:{}/", args.proxy_port),
                "capture_logs": {
                    "via_redirect": format!("{} > fault.log 2>&1", shell),
                    "via_fault_flag_hint": "fault supports global flags like --log-file fault.log (see: fault --help)"
                },
            }
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(EXIT_SUCCESS);
    }

    println!("{}", shell);
    if !notes.is_empty() {
        for n in notes {
            println!("{}", n);
        }
    }
    println!("Traffic: curl -i http://127.0.0.1:{}/", args.proxy_port);
    println!("Logs: {} > fault.log 2>&1", shell);
    println!("Tip: fault also supports --log-file fault.log (global flag)");

    Ok(EXIT_SUCCESS)
}

pub fn execute_list(json: bool) -> Result<i32> {
    use crate::exit_codes::EXIT_SUCCESS;

    let recipes = vec![
        (
            "latency",
            "Inject constant latency",
            "latency 200ms for 30s",
        ),
        (
            "jitter",
            "Inject jitter (per-operation variance)",
            "jitter 80ms at 8hz for 30s",
        ),
        ("bandwidth", "Cap bandwidth", "bandwidth 512 KBps for 30s"),
        ("drop", "Enable packet loss", "drop 5% for 30s"),
        (
            "blackhole",
            "Blackhole traffic (drop all packets)",
            "blackhole for 10s",
        ),
        (
            "http",
            "Return an HTTP status immediately",
            "http 500 prob 0.25 for 30s",
        ),
    ];

    if json {
        let out = serde_json::json!({
            "schema_version": "unfault.fault_plan_recipes.v1",
            "recipes": recipes.iter().map(|(k, desc, ex)| serde_json::json!({
                "kind": k,
                "description": desc,
                "example": ex,
            })).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(EXIT_SUCCESS);
    }

    println!("Supported scenarios:");
    for (k, desc, ex) in recipes {
        println!("- {}: {} (e.g. '{}')", k, desc, ex);
    }

    Ok(EXIT_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_latency_with_duration() {
        let r = parse_recipe("latency 200ms for 10s").unwrap();
        assert_eq!(r.kind, RecipeKind::Latency);
        assert_eq!(r.duration, "10s");
        assert_eq!(r.latency_ms, Some(200));
    }

    #[test]
    fn parses_jitter_defaults_frequency() {
        let r = parse_recipe("jitter 80ms for 10s").unwrap();
        assert_eq!(r.kind, RecipeKind::Jitter);
        assert_eq!(r.jitter_amplitude_ms, Some(80.0));
        assert_eq!(r.jitter_frequency_hz, Some(5.0));
    }

    #[test]
    fn parses_jitter_with_frequency() {
        let r = parse_recipe("jitter 80ms at 8hz for 10s").unwrap();
        assert_eq!(r.jitter_frequency_hz, Some(8.0));
    }

    #[test]
    fn parses_bandwidth() {
        let r = parse_recipe("bandwidth 512 KBps for 10s").unwrap();
        assert_eq!(r.kind, RecipeKind::Bandwidth);
        assert_eq!(r.bandwidth_rate, Some(512));
        assert_eq!(r.bandwidth_unit.as_deref(), Some("KBps"));
    }

    #[test]
    fn builds_latency_command() {
        let r = parse_recipe("latency 200ms for 10s").unwrap();
        let (_argv, shell, _notes) = build_fault_run_command(&r, 9090, "http://127.0.0.1:8000");
        assert!(shell.contains("fault run"));
        assert!(shell.contains("--with-latency"));
        assert!(shell.contains("--latency-min 200"));
        assert!(shell.contains("\"9090=http://127.0.0.1:8000\""));
    }
}

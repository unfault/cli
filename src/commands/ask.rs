//! # Ask Command
//!
//! Implements the ask command for querying project health via RAG.
//!
//! ## Usage
//!
//! ```bash
//! # Ask a question about your project
//! unfault ask "How is my service doing?"
//!
//! # Ask with a specific workspace filter
//! unfault ask "What are the main stability concerns?" --workspace wks_abc123
//!
//! # Get JSON output
//! unfault ask "Show performance issues" --json
//! ```

use anyhow::Result;
use colored::Colorize;
use termimad::MadSkin;

use crate::api::llm::{build_llm_context, LlmClient};
use crate::api::rag::{RAGQueryRequest, RAGQueryResponse};
use crate::api::ApiClient;
use crate::config::Config;
use crate::exit_codes::*;

/// Arguments for the ask command
#[derive(Debug)]
pub struct AskArgs {
    /// The natural language query
    pub query: String,
    /// Optional workspace ID to scope the query
    pub workspace_id: Option<String>,
    /// Maximum sessions to retrieve
    pub max_sessions: Option<i32>,
    /// Maximum findings to retrieve
    pub max_findings: Option<i32>,
    /// Similarity threshold
    pub similarity_threshold: Option<f64>,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Skip LLM and show raw context only
    pub no_llm: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Execute the ask command
///
/// Queries project health using RAG and displays the results.
///
/// # Arguments
///
/// * `args` - Command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Query completed successfully
/// * `Ok(EXIT_CONFIG_ERROR)` - Not logged in or configuration error
/// * `Ok(EXIT_AUTH_ERROR)` - API key is invalid
/// * `Ok(EXIT_NETWORK_ERROR)` - Cannot reach the API
/// * `Ok(EXIT_SERVICE_UNAVAILABLE)` - Embedding service not available
pub async fn execute(args: AskArgs) -> Result<i32> {
    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} Not logged in. Run `unfault login` first.",
                "Error:".red().bold()
            );
            if args.verbose {
                eprintln!("  {}: {}", "Details".dimmed(), e);
            }
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    // Create API client
    let api_client = ApiClient::new(config.base_url());

    // Build request
    let request = RAGQueryRequest {
        query: args.query.clone(),
        workspace_id: args.workspace_id.clone(),
        max_sessions: args.max_sessions,
        max_findings: args.max_findings,
        similarity_threshold: args.similarity_threshold,
    };

    if args.verbose {
        eprintln!("{} Querying: {}", "→".cyan(), args.query);
        if let Some(ref ws) = args.workspace_id {
            eprintln!("{} Workspace: {}", "→".cyan(), ws);
        }
    }

    // Execute query
    let response = match api_client.query_rag(&config.api_key, &request).await {
        Ok(response) => response,
        Err(e) => {
            if e.is_auth_error() {
                eprintln!(
                    "{} Authentication failed. Run `unfault login` to re-authenticate.",
                    "Error:".red().bold()
                );
                if args.verbose {
                    eprintln!("  {}: {}", "Details".dimmed(), e);
                    eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
                }
                return Ok(EXIT_AUTH_ERROR);
            }
            if e.is_network_error() {
                eprintln!(
                    "{} Cannot reach the API. Check your internet connection.",
                    "Error:".red().bold()
                );
                if args.verbose {
                    eprintln!("  {}: {}", "Details".dimmed(), e);
                    eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
                }
                return Ok(EXIT_NETWORK_ERROR);
            }
            if e.is_server_error() {
                eprintln!(
                    "{} {}",
                    "Error:".red().bold(),
                    e
                );
                if args.verbose {
                    eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
                }
                return Ok(EXIT_SERVICE_UNAVAILABLE);
            }
            eprintln!("{} {}", "Error:".red().bold(), e);
            if args.verbose {
                eprintln!("  {}: {}", "API URL".dimmed(), config.base_url());
            }
            return Ok(EXIT_ERROR);
        }
    };

    // Check if LLM is configured for generating AI response (unless --no-llm)
    let llm_response = if !args.no_llm && config.llm_ready() {
        let llm_config = config.llm.as_ref().unwrap();
        
        if args.verbose {
            eprintln!(
                "{} Using {} ({}) for AI response...",
                "→".cyan(),
                llm_config.provider,
                llm_config.model
            );
        }
        
        // Build rich context for LLM
        let llm_context = build_llm_context(
            &response.context_summary,
            &response.sessions,
            &response.findings,
        );
        
        // Create LLM client and generate response with streaming
        match LlmClient::new_with_options(llm_config, args.verbose) {
            Ok(client) => {
                // Print header before streaming starts (include model info)
                println!();
                println!(
                    "{} {} {}",
                    "🤖".green(),
                    "AI Analysis".bold().underline(),
                    format!("({})", llm_config.model).dimmed()
                );
                println!();

                // Stream tokens directly to stdout
                let result = client.generate_streaming(&args.query, &llm_context).await;
                
                match result {
                    Ok(text) => {
                        // Treat empty or whitespace-only responses as failures
                        let trimmed = text.trim();
                        if trimmed.is_empty() {
                            if args.verbose {
                                eprintln!("{} LLM returned empty response", "⚠".yellow());
                            }
                            None
                        } else {
                            // Already printed via streaming, store for output logic
                            Some(trimmed.to_string())
                        }
                    }
                    Err(e) => {
                        if args.verbose {
                            eprintln!("{} LLM error: {}", "⚠".yellow(), e);
                        }
                        None
                    }
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("{} LLM client error: {}", "⚠".yellow(), e);
                }
                None
            }
        }
    } else {
        None
    };

    // Output results
    // Note: when LLM is used with streaming, response was already printed to stdout
    let streamed = llm_response.is_some();
    if args.json {
        output_json(&response, llm_response.as_deref())?;
    } else {
        output_formatted(&response, llm_response.as_deref(), args.verbose, config.llm_ready(), streamed);
    }

    Ok(EXIT_SUCCESS)
}

/// Output response as JSON
fn output_json(response: &RAGQueryResponse, llm_response: Option<&str>) -> Result<()> {
    // Create a combined response with LLM output if available
    let output = if let Some(llm_text) = llm_response {
        serde_json::json!({
            "query": response.query,
            "answer": llm_text,
            "sessions": response.sessions,
            "findings": response.findings,
            "sources": response.sources,
            "context_summary": response.context_summary,
        })
    } else {
        serde_json::to_value(response)?
    };
    
    let json = serde_json::to_string_pretty(&output)?;
    println!("{}", json);
    Ok(())
}

/// Output response as formatted text
/// Maximum width for markdown rendering
const MARKDOWN_MAX_WIDTH: usize = 80;

/// Create a styled skin for terminal markdown rendering
fn create_markdown_skin() -> MadSkin {
    let mut skin = MadSkin::default();
    // Customize colors for better terminal appearance
    skin.set_headers_fg(termimad::crossterm::style::Color::Cyan);
    skin.bold.set_fg(termimad::crossterm::style::Color::White);
    skin.italic.set_fg(termimad::crossterm::style::Color::Yellow);
    skin.code_block.set_fgbg(
        termimad::crossterm::style::Color::Green,
        termimad::crossterm::style::Color::Reset,
    );
    skin
}

/// Render markdown text with a maximum width
fn render_markdown(text: &str) {
    let skin = create_markdown_skin();
    // Use write_in_area which respects width, or term_text with area
    let area = termimad::Area::new(0, 0, MARKDOWN_MAX_WIDTH as u16, u16::MAX);
    let fmt_text = termimad::FmtText::from(&skin, text, Some(area.width as usize));
    print!("{}", fmt_text);
}

fn output_formatted(response: &RAGQueryResponse, llm_response: Option<&str>, verbose: bool, has_llm: bool, streamed: bool) {
    // Print LLM response if available (this is the main answer)
    // If streamed=true, the response was already printed in real-time
    if llm_response.is_some() {
        if !streamed {
            // Non-streaming: print header and markdown-rendered response
            // Note: model info not available in output_formatted, shown in streaming path only
            println!();
            println!("{} {}", "🤖".green(), "AI Analysis".bold().underline());
            println!();
            
            // Render markdown with termimad (max 80 columns)
            if let Some(answer) = llm_response {
                render_markdown(answer);
            }
            println!();
        }
        
        // Show separator before raw context in verbose mode
        if verbose {
            println!();
            println!("{}", "─".repeat(50).dimmed());
            println!("{}", "Raw Context (verbose mode)".dimmed());
        }
    } else if !has_llm {
        // No LLM configured - show hint at top
        println!();
        println!(
            "{} {} Configure an LLM for AI-powered answers: {}",
            "💡".yellow(),
            "Tip:".yellow().bold(),
            "unfault config llm openai".cyan()
        );
    }
    
    // Print context summary (always in verbose, or when no LLM answer)
    if llm_response.is_none() || verbose {
        println!();
        println!("{}", "Context Summary".bold().underline());
        println!("{}", response.context_summary);
        println!();
    }

    // Print sessions if any (in verbose mode, or when no LLM answer)
    if (llm_response.is_none() || verbose) && !response.sessions.is_empty() {
        println!("{}", "Related Sessions".bold());
        println!("{}", "─".repeat(50).dimmed());
        
        for session in &response.sessions {
            let workspace = session.workspace_label.as_deref().unwrap_or("Unknown");
            let similarity_pct = (session.similarity * 100.0).round() as i32;
            
            println!(
                "  {} {} {} ({}% match)",
                "•".cyan(),
                workspace.bright_white(),
                format!("[{} findings]", session.total_findings).dimmed(),
                similarity_pct
            );
            
            if verbose && !session.dimension_counts.is_empty() {
                let dims: Vec<String> = session
                    .dimension_counts
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                println!("    {} {}", "Dimensions:".dimmed(), dims.join(", ").dimmed());
            }
            
            if verbose && !session.severity_counts.is_empty() {
                let sevs: Vec<String> = session
                    .severity_counts
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                println!("    {} {}", "Severities:".dimmed(), sevs.join(", ").dimmed());
            }
        }
        println!();
    }

    // Print findings if any (in verbose mode, or when no LLM answer)
    if (llm_response.is_none() || verbose) && !response.findings.is_empty() {
        println!("{}", "Related Findings".bold());
        println!("{}", "─".repeat(50).dimmed());
        
        for finding in &response.findings {
            let rule = finding.rule_id.as_deref().unwrap_or("unknown");
            let severity = finding.severity.as_deref().unwrap_or("unknown");
            let dimension = finding.dimension.as_deref().unwrap_or("unknown");
            let similarity_pct = (finding.similarity * 100.0).round() as i32;
            
            // Color severity
            let severity_colored = match severity.to_lowercase().as_str() {
                "critical" | "high" => severity.red().bold(),
                "medium" => severity.yellow(),
                "low" => severity.green(),
                _ => severity.normal(),
            };
            
            println!(
                "  {} {} [{}] ({}% match)",
                "•".cyan(),
                rule.bright_white(),
                severity_colored,
                similarity_pct
            );
            
            if let (Some(file), Some(line)) = (&finding.file_path, finding.line) {
                println!("    {} {}:{}", "→".dimmed(), file.cyan(), line);
            } else if let Some(file) = &finding.file_path {
                println!("    {} {}", "→".dimmed(), file.cyan());
            }
            
            if verbose {
                println!("    {} {}", "Dimension:".dimmed(), dimension.dimmed());
            }
        }
        println!();
    }

    // If nothing found (only show when no LLM answer)
    if llm_response.is_none() && response.sessions.is_empty() && response.findings.is_empty() {
        println!(
            "{} No relevant context found for your query.",
            "ℹ".blue()
        );
        println!("  Try running `unfault review` first to analyze your code.");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ask_args_defaults() {
        let args = AskArgs {
            query: "test query".to_string(),
            workspace_id: None,
            max_sessions: None,
            max_findings: None,
            similarity_threshold: None,
            json: false,
            no_llm: false,
            verbose: false,
        };
        assert_eq!(args.query, "test query");
        assert!(args.workspace_id.is_none());
        assert!(!args.json);
        assert!(!args.no_llm);
        assert!(!args.verbose);
    }

    #[test]
    fn test_ask_args_with_options() {
        let args = AskArgs {
            query: "How is my service?".to_string(),
            workspace_id: Some("wks_abc123".to_string()),
            max_sessions: Some(10),
            max_findings: Some(20),
            similarity_threshold: Some(0.7),
            json: true,
            no_llm: false,
            verbose: true,
        };
        assert_eq!(args.query, "How is my service?");
        assert_eq!(args.workspace_id, Some("wks_abc123".to_string()));
        assert_eq!(args.max_sessions, Some(10));
        assert!(args.json);
        assert!(args.verbose);
    }
}
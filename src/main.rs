//! # Unfault CLI
//!
//! Unfault — a calm reviewer for thoughtful engineers
//!
//! Unfault analyzes your code for clarity, boundaries, and behavior,
//! highlighting places where decisions matter — before reality does.
//!
//! You write the code. Unfault helps you build it right.
//!
//! ## Usage
//!
//! ```bash
//! # Authenticate
//! unfault login
//!
//! # Analyze code
//! unfault review
//!
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use unfault::commands;

/// Output format options for commands
#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    /// Basic output showing only header and summary line (default)
    Basic,
    /// Concise output with just summary statistics
    Concise,
    /// Full output with detailed analysis and findings
    Full,
    /// JSON output format
    Json,
}

/// Main CLI structure
#[derive(Parser)]
#[command(name = "unfault")]
#[command(about = "Unfault — a calm reviewer for thoughtful engineers", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
/// Available CLI commands
#[derive(Subcommand)]
enum Commands {
    /// Ask questions about project health using RAG
    Ask {
        /// Natural language query about project health
        #[arg(value_name = "QUERY")]
        query: String,
        /// Scope query to a specific workspace ID
        #[arg(long, short = 'w', value_name = "WORKSPACE_ID")]
        workspace: Option<String>,
        /// Maximum session contexts to retrieve (1-20)
        #[arg(long, value_name = "COUNT", default_value = "5")]
        max_sessions: i32,
        /// Maximum finding contexts to retrieve (1-50)
        #[arg(long, value_name = "COUNT", default_value = "10")]
        max_findings: i32,
        /// Minimum similarity threshold (0.0-1.0)
        #[arg(long, value_name = "THRESHOLD", default_value = "0.5")]
        threshold: f64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Skip LLM and show raw context only
        #[arg(long)]
        no_llm: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Manage CLI configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Authenticate with Unfault using device flow
    Login,
    /// Analyze code and get recommendations
    Review {
        /// Output format (basic: header + summary, concise: brief findings, full: detailed analysis)
        #[arg(long, value_name = "OUTPUT", default_value = "basic")]
        output: OutputFormat,
        /// Enable verbose output (dumps raw API responses)
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Override the detected profile (e.g., python_fastapi_backend)
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// Dimensions to analyze (can be specified multiple times)
        /// Available: stability, correctness, performance, scalability
        /// Default: all dimensions from the profile
        #[arg(long, short = 'd', value_name = "DIMENSION")]
        dimension: Vec<String>,
    },
    /// Check authentication and service configuration status
    Status,
}

/// Config subcommands
#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show {
        /// Show full secrets instead of masked values
        #[arg(long)]
        show_secrets: bool,
    },
    /// Manage LLM configuration for AI-powered insights
    Llm {
        #[command(subcommand)]
        command: LlmCommands,
    },
}

/// LLM subcommands
#[derive(Subcommand)]
enum LlmCommands {
    /// Configure OpenAI as LLM provider
    Openai {
        /// Model name (e.g., gpt-4, gpt-4o, gpt-3.5-turbo)
        #[arg(long, short = 'm', default_value = "gpt-4")]
        model: String,
        /// API key (optional, prefers OPENAI_API_KEY env var)
        #[arg(long, short = 'k')]
        api_key: Option<String>,
    },
    /// Configure Anthropic as LLM provider
    Anthropic {
        /// Model name (e.g., claude-3-5-sonnet-latest, claude-3-opus)
        #[arg(long, short = 'm', default_value = "claude-3-5-sonnet-latest")]
        model: String,
        /// API key (optional, prefers ANTHROPIC_API_KEY env var)
        #[arg(long, short = 'k')]
        api_key: Option<String>,
    },
    /// Configure local Ollama as LLM provider
    Ollama {
        /// Ollama API endpoint
        #[arg(long, short = 'e', default_value = "http://localhost:11434")]
        endpoint: String,
        /// Model name (e.g., llama3.2, mistral, codellama)
        #[arg(long, short = 'm', default_value = "llama3.2")]
        model: String,
    },
    /// Configure custom OpenAI-compatible endpoint
    Custom {
        /// API endpoint URL
        #[arg(long, short = 'e')]
        endpoint: String,
        /// Model name
        #[arg(long, short = 'm')]
        model: String,
        /// API key (optional)
        #[arg(long, short = 'k')]
        api_key: Option<String>,
    },
    /// Show current LLM configuration
    Show {
        /// Show full secrets instead of masked values
        #[arg(long)]
        show_secrets: bool,
    },
    /// Remove LLM configuration
    Remove,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let exit_code = run_command(cli.command).await;
    std::process::exit(exit_code);
}

async fn run_command(command: Commands) -> i32 {
    use unfault::exit_codes::*;

    match command {
        Commands::Ask {
            query,
            workspace,
            max_sessions,
            max_findings,
            threshold,
            json,
            no_llm,
            verbose,
        } => {
            let args = commands::ask::AskArgs {
                query,
                workspace_id: workspace,
                max_sessions: Some(max_sessions),
                max_findings: Some(max_findings),
                similarity_threshold: Some(threshold),
                json,
                no_llm,
                verbose,
            };
            match commands::ask::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Ask error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        Commands::Config { command } => run_config_command(command),
        Commands::Login => match commands::login::execute().await {
            Ok(exit_code) => exit_code,
            Err(e) => {
                eprintln!("Login error: {}", e);
                EXIT_CONFIG_ERROR
            }
        },
        Commands::Review { output, verbose, profile, dimension } => {
            // Convert OutputFormat to string for backward compatibility
            let output_format = match output {
                OutputFormat::Json => "json".to_string(),
                OutputFormat::Basic => "text".to_string(),
                OutputFormat::Concise => "text".to_string(),
                OutputFormat::Full => "text".to_string(),
            };
            
            // Determine output mode
            let output_mode = match output {
                OutputFormat::Basic => "basic".to_string(),
                OutputFormat::Concise => "concise".to_string(),
                OutputFormat::Full => "full".to_string(),
                OutputFormat::Json => "full".to_string(), // JSON is always full
            };
            
            let args = commands::review::ReviewArgs {
                output_format,
                output_mode,
                verbose,
                profile,
                dimensions: if dimension.is_empty() { None } else { Some(dimension) },
            };
            match commands::review::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Review error: {}", e);
                    EXIT_CONFIG_ERROR
                }
            }
        }
        Commands::Status => match commands::status::execute().await {
            Ok(exit_code) => exit_code,
            Err(e) => {
                eprintln!("Status error: {}", e);
                EXIT_CONFIG_ERROR
            }
        },
    }
}

fn run_config_command(command: ConfigCommands) -> i32 {
    use unfault::exit_codes::*;

    match command {
        ConfigCommands::Show { show_secrets } => {
            let args = commands::config::ConfigShowArgs { show_secrets };
            match commands::config::execute_show(args) {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Config error: {}", e);
                    EXIT_CONFIG_ERROR
                }
            }
        }
        ConfigCommands::Llm { command } => run_llm_command(command),
    }
}

fn run_llm_command(command: LlmCommands) -> i32 {
    use commands::config::{ConfigLlmArgs, LlmProvider};
    use unfault::exit_codes::*;

    let args = match command {
        LlmCommands::Openai { model, api_key } => {
            ConfigLlmArgs::Set(LlmProvider::OpenAI { model, api_key })
        }
        LlmCommands::Anthropic { model, api_key } => {
            ConfigLlmArgs::Set(LlmProvider::Anthropic { model, api_key })
        }
        LlmCommands::Ollama { endpoint, model } => {
            ConfigLlmArgs::Set(LlmProvider::Ollama { endpoint, model })
        }
        LlmCommands::Custom { endpoint, model, api_key } => {
            ConfigLlmArgs::Set(LlmProvider::Custom { endpoint, model, api_key })
        }
        LlmCommands::Show { show_secrets } => {
            ConfigLlmArgs::Show { show_secrets }
        }
        LlmCommands::Remove => ConfigLlmArgs::Remove,
    };

    match commands::config::execute_llm(args) {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("Config LLM error: {}", e);
            EXIT_CONFIG_ERROR
        }
    }
}

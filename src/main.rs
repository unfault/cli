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

/// Initialize logger based on verbose flag
fn init_logger(verbose: bool) {
    let mut log_builder = env_logger::Builder::from_default_env();
    if verbose {
        log_builder.filter_level(log::LevelFilter::Debug);
    } else {
        log_builder.filter_level(log::LevelFilter::Info);
    }
    log_builder.init();
}

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
    /// SARIF output format for GitHub Code Scanning / IDE integration
    Sarif,
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
        /// Scope query to a specific workspace ID (auto-detected from current directory if not provided)
        #[arg(long, short = 'w', value_name = "WORKSPACE_ID")]
        workspace: Option<String>,
        /// Workspace path to auto-detect workspace ID from (defaults to current directory)
        #[arg(long, short = 'p', value_name = "PATH")]
        path: Option<String>,
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
        /// Use the configured LLM for a longer answer
        #[arg(long)]
        llm: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Manage CLI configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Query the code graph for impact analysis, dependencies, and critical files
    Graph {
        #[command(subcommand)]
        command: GraphCommands,
    },
    /// Authenticate with Unfault using device flow
    Login,
    /// Start the LSP server for IDE integration
    Lsp {
        /// Enable verbose logging to stderr
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Use stdio transport (default, added for compatibility with language clients)
        #[arg(long, hide = true)]
        stdio: bool,
    },
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
        /// Auto-apply all suggested fixes
        #[arg(long)]
        fix: bool,
        /// Show what fixes would be applied without actually applying them
        #[arg(long)]
        dry_run: bool,
        /// Use legacy server-side parsing (sends source code to server)
        #[arg(long)]
        server_parse: bool,
        /// Print raw findings instead of hotspot summary (advanced, very large output)
        #[arg(long, hide = true)]
        raw_findings: bool,
    },
    /// Check authentication and service configuration status
    Status,
}

/// Graph subcommands
#[derive(Subcommand)]
enum GraphCommands {
    /// Analyze impact: "What breaks if I change this file?"
    Impact {
        /// File path to analyze
        #[arg(value_name = "FILE")]
        file_path: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Maximum depth for transitive analysis (1-10)
        #[arg(long, value_name = "DEPTH", default_value = "5")]
        max_depth: i32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Analyze function impact: "What breaks if I change this function?"
    FunctionImpact {
        /// Function in format file:function
        #[arg(value_name = "FUNCTION")]
        function: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Maximum depth for transitive analysis (1-10)
        #[arg(long, value_name = "DEPTH", default_value = "5")]
        max_depth: i32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Find files that use a specific library
    Library {
        /// Library name to search for (e.g., "requests", "fastapi")
        #[arg(value_name = "LIBRARY")]
        library_name: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Find external dependencies of a file
    Deps {
        /// File path to analyze
        #[arg(value_name = "FILE")]
        file_path: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Find the most critical/hub files in the codebase
    Critical {
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Maximum number of files to return (1-50)
        #[arg(long, short = 'n', value_name = "COUNT", default_value = "10")]
        limit: i32,
        /// Metric to sort by
        #[arg(long, value_name = "METRIC", default_value = "in_degree")]
        sort_by: SortMetric,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Get code graph statistics
    Stats {
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Build and dump the local code graph (for debugging)
    Dump {
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output only call edges (useful for debugging call graph issues)
        #[arg(long)]
        calls_only: bool,
        /// Output only specific file's information
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
}

/// Centrality sort metric options
#[derive(Clone, Debug, ValueEnum)]
pub enum SortMetric {
    /// Sort by number of files that import this file (most critical dependencies)
    InDegree,
    /// Sort by number of files this file imports
    OutDegree,
    /// Sort by total connectivity (in + out)
    TotalDegree,
    /// Sort by number of external libraries used
    LibraryUsage,
    /// Sort by weighted importance score
    ImportanceScore,
}

impl SortMetric {
    fn as_str(&self) -> &'static str {
        match self {
            SortMetric::InDegree => "in_degree",
            SortMetric::OutDegree => "out_degree",
            SortMetric::TotalDegree => "total_degree",
            SortMetric::LibraryUsage => "library_usage",
            SortMetric::ImportanceScore => "importance_score",
        }
    }
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
    // Initialize rayon with larger stack size for tree-sitter parsing
    // Tree-sitter uses deep recursion which can overflow the default 2MB stack
    // especially for large codebases like kubernetes
    rayon::ThreadPoolBuilder::new()
        .stack_size(8 * 1024 * 1024) // 8MB per thread
        .build_global()
        .unwrap();

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
            path,
            max_sessions,
            max_findings,
            threshold,
            json,
            llm,
            verbose,
        } => {
            let args = commands::ask::AskArgs {
                query,
                workspace_id: workspace,
                workspace_path: path,
                max_sessions: Some(max_sessions),
                max_findings: Some(max_findings),
                similarity_threshold: Some(threshold),
                json,
                llm,
                verbose,
            };
            init_logger(verbose);
            match commands::ask::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Ask error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        Commands::Config { command } => run_config_command(command),
        Commands::Graph { command } => run_graph_command(command).await,
        Commands::Login => match commands::login::execute().await {
            Ok(exit_code) => exit_code,
            Err(e) => {
                eprintln!("Login error: {}", e);
                EXIT_CONFIG_ERROR
            }
        },
        Commands::Lsp { verbose, stdio: _ } => {
            init_logger(verbose);
            // stdio flag is just for compatibility with language clients, we always use stdio
            let args = commands::lsp::LspArgs { verbose };
            match commands::lsp::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("LSP error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        Commands::Review {
            output,
            verbose,
            profile,
            dimension,
            fix,
            dry_run,
            server_parse,
            raw_findings,
        } => {
            init_logger(verbose);
            // Convert OutputFormat to string for backward compatibility
            let output_format = match output {
                OutputFormat::Json => "json".to_string(),
                OutputFormat::Sarif => "sarif".to_string(),
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
                OutputFormat::Sarif => "full".to_string(), // SARIF is always full
            };

            let args = commands::review::ReviewArgs {
                output_format,
                output_mode,
                verbose,
                profile,
                dimensions: if dimension.is_empty() {
                    None
                } else {
                    Some(dimension)
                },
                fix,
                dry_run,
                server_parse,
                raw_findings,
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
        LlmCommands::Custom {
            endpoint,
            model,
            api_key,
        } => ConfigLlmArgs::Set(LlmProvider::Custom {
            endpoint,
            model,
            api_key,
        }),
        LlmCommands::Show { show_secrets } => ConfigLlmArgs::Show { show_secrets },
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

async fn run_graph_command(command: GraphCommands) -> i32 {
    use unfault::exit_codes::*;

    match command {
        GraphCommands::Impact {
            file_path,
            session,
            workspace,
            max_depth,
            json,
            verbose,
        } => {
            let args = commands::graph::ImpactArgs {
                session_id: session,
                workspace_path: workspace,
                file_path,
                max_depth,
                json,
                verbose,
            };
            match commands::graph::execute_impact(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph impact error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::FunctionImpact {
            function,
            session,
            workspace,
            max_depth,
            json,
            verbose,
        } => {
            let args = commands::graph::FunctionImpactArgs {
                session_id: session,
                workspace_path: workspace,
                function,
                max_depth,
                json,
                verbose,
            };
            match commands::graph::execute_function_impact(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph function impact error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Library {
            library_name,
            session,
            workspace,
            json,
            verbose,
        } => {
            let args = commands::graph::LibraryArgs {
                session_id: session,
                workspace_path: workspace,
                library_name,
                json,
                verbose,
            };
            match commands::graph::execute_library(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph library error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Deps {
            file_path,
            session,
            workspace,
            json,
            verbose,
        } => {
            let args = commands::graph::DepsArgs {
                session_id: session,
                workspace_path: workspace,
                file_path,
                json,
                verbose,
            };
            match commands::graph::execute_deps(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph deps error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Critical {
            session,
            workspace,
            limit,
            sort_by,
            json,
            verbose,
        } => {
            let args = commands::graph::CriticalArgs {
                session_id: session,
                workspace_path: workspace,
                limit,
                sort_by: sort_by.as_str().to_string(),
                json,
                verbose,
            };
            match commands::graph::execute_critical(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph critical error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Stats {
            session,
            workspace,
            json,
            verbose,
        } => {
            let args = commands::graph::StatsArgs {
                session_id: session,
                workspace_path: workspace,
                json,
                verbose,
            };
            match commands::graph::execute_stats(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph stats error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Dump {
            workspace,
            calls_only,
            file,
            verbose,
        } => {
            let args = commands::graph::DumpArgs {
                workspace_path: workspace,
                calls_only,
                file,
                verbose,
            };
            match commands::graph::execute_dump(args) {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph dump error: {}", e);
                    EXIT_ERROR
                }
            }
        }
    }
}

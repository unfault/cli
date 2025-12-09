//! # Config Command
//!
//! Manages CLI configuration including LLM settings for the `ask` command.
//!
//! ## Usage
//!
//! ```bash
//! # Show current configuration
//! unfault config show
//!
//! # Configure OpenAI for insights
//! unfault config llm openai --model gpt-4
//!
//! # Configure Anthropic
//! unfault config llm anthropic --model claude-3-5-sonnet-latest
//!
//! # Configure local Ollama
//! unfault config llm ollama --endpoint http://localhost:11434 --model llama3.2
//!
//! # Configure custom OpenAI-compatible endpoint
//! unfault config llm custom --endpoint https://api.example.com/v1 --model custom-model
//!
//! # Show current LLM configuration
//! unfault config llm show
//!
//! # Remove LLM configuration
//! unfault config llm remove
//! ```

use anyhow::Result;
use colored::Colorize;

use crate::config::{Config, LlmConfig};
use crate::exit_codes::*;

/// LLM provider types for configuration
#[derive(Debug, Clone)]
pub enum LlmProvider {
    /// OpenAI API (GPT-4, GPT-3.5, etc.)
    OpenAI {
        model: String,
        api_key: Option<String>,
    },
    /// Anthropic API (Claude models)
    Anthropic {
        model: String,
        api_key: Option<String>,
    },
    /// Local Ollama instance
    Ollama {
        endpoint: String,
        model: String,
    },
    /// Custom OpenAI-compatible endpoint
    Custom {
        endpoint: String,
        model: String,
        api_key: Option<String>,
    },
}

/// Arguments for the config show command
#[derive(Debug)]
pub struct ConfigShowArgs {
    /// Show full API key (default: masked)
    pub show_secrets: bool,
}

/// Arguments for the config llm command
#[derive(Debug)]
pub enum ConfigLlmArgs {
    /// Configure an LLM provider
    Set(LlmProvider),
    /// Show current LLM configuration
    Show { show_secrets: bool },
    /// Remove LLM configuration
    Remove,
}

/// Execute the config show command
///
/// Displays all current configuration settings.
///
/// # Arguments
///
/// * `args` - Command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Configuration displayed successfully
/// * `Ok(EXIT_CONFIG_ERROR)` - No configuration found
pub fn execute_show(args: ConfigShowArgs) -> Result<i32> {
    let config = match Config::load() {
        Ok(config) => config,
        Err(_) => {
            eprintln!(
                "{} No configuration found. Run `unfault login` first.",
                "Error:".red().bold()
            );
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    println!();
    println!("{}", "Unfault Configuration".bold().underline());
    println!();

    // Authentication
    println!("{}", "Authentication".cyan().bold());
    println!("  {} {}", "API Key:".dimmed(), mask_key(&config.api_key));
    println!("  {} {}", "Base URL:".dimmed(), config.base_url());
    println!();

    // LLM Configuration
    println!("{}", "LLM (BYOLLM)".cyan().bold());
    if let Some(ref llm) = config.llm {
        println!("  {} {}", "Provider:".dimmed(), llm.provider);
        println!("  {} {}", "Endpoint:".dimmed(), llm.endpoint);
        println!("  {} {}", "Model:".dimmed(), llm.model);
        if let Some(ref env_var) = llm.api_key_env {
            let has_key = std::env::var(env_var).is_ok();
            let status = if has_key {
                "✓ set".green().to_string()
            } else {
                "✗ not set".red().to_string()
            };
            println!("  {} {} ({})", "API Key Env:".dimmed(), env_var, status);
        }
        if llm.api_key.is_some() {
            let display = if args.show_secrets {
                llm.api_key.as_ref().unwrap().clone()
            } else {
                llm.masked_api_key().unwrap_or_else(|| "****".to_string())
            };
            println!("  {} {}", "API Key:".dimmed(), display);
        }
        let ready = if llm.is_ready() {
            "✓ ready".green()
        } else {
            "✗ not ready (API key missing)".red()
        };
        println!("  {} {}", "Status:".dimmed(), ready);
    } else {
        println!("  {}", "Not configured".dimmed());
        println!();
        println!("  {} Configure with:", "→".cyan());
        println!("    unfault config llm openai --model gpt-4");
        println!("    unfault config llm anthropic --model claude-3-5-sonnet-latest");
        println!("    unfault config llm ollama --endpoint http://localhost:11434 --model llama3.2");
    }
    println!();

    Ok(EXIT_SUCCESS)
}

/// Execute the config llm command
///
/// Configures, shows, or removes LLM settings.
///
/// # Arguments
///
/// * `args` - Command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Operation completed successfully
/// * `Ok(EXIT_CONFIG_ERROR)` - Configuration error
pub fn execute_llm(args: ConfigLlmArgs) -> Result<i32> {
    match args {
        ConfigLlmArgs::Set(provider) => set_llm_config(provider),
        ConfigLlmArgs::Show { show_secrets } => show_llm_config(show_secrets),
        ConfigLlmArgs::Remove => remove_llm_config(),
    }
}

/// Set LLM configuration
fn set_llm_config(provider: LlmProvider) -> Result<i32> {
    let mut config = match Config::load() {
        Ok(config) => config,
        Err(_) => {
            eprintln!(
                "{} No configuration found. Run `unfault login` first.",
                "Error:".red().bold()
            );
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    let llm_config = match provider {
        LlmProvider::OpenAI { model, api_key } => {
            let mut cfg = LlmConfig::openai(&model);
            if let Some(key) = api_key {
                cfg.api_key = Some(key);
            }
            cfg
        }
        LlmProvider::Anthropic { model, api_key } => {
            let mut cfg = LlmConfig::anthropic(&model);
            if let Some(key) = api_key {
                cfg.api_key = Some(key);
            }
            cfg
        }
        LlmProvider::Ollama { endpoint, model } => {
            LlmConfig::ollama(&endpoint, &model)
        }
        LlmProvider::Custom { endpoint, model, api_key } => {
            let mut cfg = LlmConfig::custom(&endpoint, &model);
            cfg.api_key = api_key;
            cfg
        }
    };

    let provider_name = llm_config.provider.clone();
    let model_name = llm_config.model.clone();

    config.llm = Some(llm_config.clone());
    config.save()?;

    println!();
    println!(
        "{} LLM configured successfully!",
        "✓".green().bold()
    );
    println!();
    println!("  {} {}", "Provider:".dimmed(), provider_name);
    println!("  {} {}", "Model:".dimmed(), model_name);
    println!("  {} {}", "Endpoint:".dimmed(), llm_config.endpoint);

    // Check if API key is available
    if !llm_config.is_ready() {
        println!();
        eprintln!(
            "{} API key not found. Set the {} environment variable.",
            "⚠".yellow().bold(),
            llm_config.api_key_env.as_deref().unwrap_or("API_KEY")
        );
    } else {
        println!();
        println!(
            "  {} Ready to use with `unfault ask`",
            "→".cyan()
        );
    }
    println!();

    Ok(EXIT_SUCCESS)
}

/// Show current LLM configuration
fn show_llm_config(show_secrets: bool) -> Result<i32> {
    let config = match Config::load() {
        Ok(config) => config,
        Err(_) => {
            eprintln!(
                "{} No configuration found. Run `unfault login` first.",
                "Error:".red().bold()
            );
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    println!();
    println!("{}", "LLM Configuration".bold().underline());
    println!();

    if let Some(ref llm) = config.llm {
        println!("  {} {}", "Provider:".dimmed(), llm.provider);
        println!("  {} {}", "Endpoint:".dimmed(), llm.endpoint);
        println!("  {} {}", "Model:".dimmed(), llm.model);

        if let Some(ref env_var) = llm.api_key_env {
            let has_key = std::env::var(env_var).is_ok();
            let status = if has_key {
                "✓ set".green().to_string()
            } else {
                "✗ not set".red().to_string()
            };
            println!("  {} {} ({})", "API Key Env:".dimmed(), env_var, status);
        }

        if llm.api_key.is_some() {
            let display = if show_secrets {
                llm.api_key.as_ref().unwrap().clone()
            } else {
                llm.masked_api_key().unwrap_or_else(|| "****".to_string())
            };
            println!("  {} {}", "API Key:".dimmed(), display);
        }

        let ready = if llm.is_ready() {
            "✓ ready".green()
        } else {
            "✗ not ready (API key missing)".red()
        };
        println!();
        println!("  {} {}", "Status:".dimmed(), ready);
    } else {
        println!("  {}", "Not configured".dimmed());
        println!();
        println!("  {} Configure with:", "→".cyan());
        println!("    unfault config llm openai --model gpt-4");
        println!("    unfault config llm anthropic --model claude-3-5-sonnet-latest");
        println!("    unfault config llm ollama --endpoint http://localhost:11434 --model llama3.2");
    }
    println!();

    Ok(EXIT_SUCCESS)
}

/// Remove LLM configuration
fn remove_llm_config() -> Result<i32> {
    let mut config = match Config::load() {
        Ok(config) => config,
        Err(_) => {
            eprintln!(
                "{} No configuration found. Run `unfault login` first.",
                "Error:".red().bold()
            );
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    if config.llm.is_none() {
        println!();
        println!(
            "{} LLM configuration is not set.",
            "ℹ".blue()
        );
        println!();
        return Ok(EXIT_SUCCESS);
    }

    config.remove_llm();
    config.save()?;

    println!();
    println!(
        "{} LLM configuration removed.",
        "✓".green().bold()
    );
    println!();

    Ok(EXIT_SUCCESS)
}

/// Mask an API key for display
fn mask_key(key: &str) -> String {
    if key.len() > 8 {
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    } else {
        "****".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_key_long() {
        let key = "sk_live_1234567890abcdef";
        let masked = mask_key(key);
        assert_eq!(masked, "sk_l...cdef");
    }

    #[test]
    fn test_mask_key_short() {
        let key = "short";
        let masked = mask_key(key);
        assert_eq!(masked, "****");
    }

    #[test]
    fn test_llm_provider_openai() {
        let provider = LlmProvider::OpenAI {
            model: "gpt-4".to_string(),
            api_key: None,
        };
        match provider {
            LlmProvider::OpenAI { model, api_key } => {
                assert_eq!(model, "gpt-4");
                assert!(api_key.is_none());
            }
            _ => panic!("Expected OpenAI provider"),
        }
    }

    #[test]
    fn test_llm_provider_anthropic() {
        let provider = LlmProvider::Anthropic {
            model: "claude-3-5-sonnet-latest".to_string(),
            api_key: Some("test-key".to_string()),
        };
        match provider {
            LlmProvider::Anthropic { model, api_key } => {
                assert_eq!(model, "claude-3-5-sonnet-latest");
                assert_eq!(api_key, Some("test-key".to_string()));
            }
            _ => panic!("Expected Anthropic provider"),
        }
    }

    #[test]
    fn test_llm_provider_ollama() {
        let provider = LlmProvider::Ollama {
            endpoint: "http://localhost:11434".to_string(),
            model: "llama3.2".to_string(),
        };
        match provider {
            LlmProvider::Ollama { endpoint, model } => {
                assert_eq!(endpoint, "http://localhost:11434");
                assert_eq!(model, "llama3.2");
            }
            _ => panic!("Expected Ollama provider"),
        }
    }

    #[test]
    fn test_llm_provider_custom() {
        let provider = LlmProvider::Custom {
            endpoint: "https://api.example.com/v1".to_string(),
            model: "custom-model".to_string(),
            api_key: None,
        };
        match provider {
            LlmProvider::Custom { endpoint, model, api_key } => {
                assert_eq!(endpoint, "https://api.example.com/v1");
                assert_eq!(model, "custom-model");
                assert!(api_key.is_none());
            }
            _ => panic!("Expected Custom provider"),
        }
    }
}
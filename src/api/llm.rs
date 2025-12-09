//! # LLM Client
//!
//! This module provides a client for calling LLM APIs to generate responses
//! based on RAG context. Supports OpenAI, Anthropic, Ollama, and custom endpoints.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use unfault::api::llm::LlmClient;
//! use unfault::config::LlmConfig;
//!
//! async fn generate_response() -> Result<String, unfault::api::llm::LlmError> {
//!     let config = LlmConfig::openai("gpt-4");
//!     let client = LlmClient::new(&config)?;
//!     let response = client.generate(
//!         "How is my service doing?",
//!         "Retrieved 1 session with 42 findings..."
//!     ).await?;
//!     Ok(response)
//! }
//! ```

use crate::config::LlmConfig;
use colored::Colorize;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Write};

// =============================================================================
// Error Types
// =============================================================================

/// Errors from LLM operations.
#[derive(Debug)]
pub enum LlmError {
    /// API key is missing or cannot be found.
    MissingApiKey { env_var: String },
    /// Network error communicating with LLM API.
    Network { message: String },
    /// LLM API returned an error.
    ApiError { status: u16, message: String },
    /// Failed to parse response.
    ParseError { message: String },
    /// Provider not supported.
    UnsupportedProvider { provider: String },
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::MissingApiKey { env_var } => {
                write!(f, "API key not found. Set {} environment variable", env_var)
            }
            LlmError::Network { message } => write!(f, "Network error: {}", message),
            LlmError::ApiError { status, message } => {
                write!(f, "API error ({}): {}", status, message)
            }
            LlmError::ParseError { message } => write!(f, "Parse error: {}", message),
            LlmError::UnsupportedProvider { provider } => {
                write!(f, "Unsupported provider: {}", provider)
            }
        }
    }
}

impl std::error::Error for LlmError {}

// =============================================================================
// OpenAI Types
// =============================================================================

#[derive(Debug, Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
}

// OpenAI streaming types
#[derive(Debug, Deserialize)]
struct OpenAIStreamChoice {
    delta: OpenAIStreamDelta,
}

#[derive(Debug, Deserialize)]
struct OpenAIStreamDelta {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIStreamResponse {
    choices: Vec<OpenAIStreamChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    message: OpenAIMessageResponse,
}

#[derive(Debug, Deserialize)]
struct OpenAIMessageResponse {
    /// Content can be null for some models (reasoning models during thinking)
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAIErrorResponse {
    error: OpenAIErrorDetail,
}

#[derive(Debug, Deserialize)]
struct OpenAIErrorDetail {
    message: String,
}

// =============================================================================
// Anthropic Types
// =============================================================================

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    messages: Vec<AnthropicMessage>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
}

// Anthropic streaming types
#[derive(Debug, Deserialize)]
struct AnthropicStreamEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    delta: Option<AnthropicStreamDelta>,
}

#[derive(Debug, Deserialize)]
struct AnthropicStreamDelta {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    text: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
}

#[derive(Debug, Deserialize)]
struct AnthropicErrorResponse {
    error: AnthropicErrorDetail,
}

#[derive(Debug, Deserialize)]
struct AnthropicErrorDetail {
    message: String,
}

// =============================================================================
// Ollama Types
// =============================================================================

#[derive(Debug, Serialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaMessageResponse {
    content: String,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    message: OllamaMessageResponse,
}

// =============================================================================
// LLM Client
// =============================================================================

/// Client for calling LLM APIs.
pub struct LlmClient {
    client: reqwest::Client,
    provider: String,
    endpoint: String,
    model: String,
    api_key: Option<String>,
    verbose: bool,
}

impl LlmClient {
    /// Create a new LLM client from configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - LLM configuration
    ///
    /// # Returns
    ///
    /// * `Ok(LlmClient)` - Client created successfully
    /// * `Err(LlmError)` - Failed to create client (e.g., missing API key)
    pub fn new(config: &LlmConfig) -> Result<Self, LlmError> {
        Self::new_with_options(config, false)
    }

    /// Create a new LLM client with verbose logging option.
    pub fn new_with_options(config: &LlmConfig, verbose: bool) -> Result<Self, LlmError> {
        // For providers that require API keys, check availability
        if config.provider != "ollama" {
            let api_key = config.get_api_key();
            if api_key.is_none() {
                let env_var = config.api_key_env.clone().unwrap_or_else(|| "API_KEY".to_string());
                return Err(LlmError::MissingApiKey { env_var });
            }
        }

        Ok(Self {
            client: reqwest::Client::new(),
            provider: config.provider.clone(),
            endpoint: config.endpoint.clone(),
            model: config.model.clone(),
            api_key: config.get_api_key(),
            verbose,
        })
    }

    /// Generate a response from the LLM.
    ///
    /// # Arguments
    ///
    /// * `query` - User's original question
    /// * `context` - RAG context to provide to the LLM
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Generated response
    /// * `Err(LlmError)` - Generation failed
    pub async fn generate(&self, query: &str, context: &str) -> Result<String, LlmError> {
        self.generate_internal(query, context, false).await
    }

    /// Generate a response from the LLM with streaming output.
    ///
    /// Tokens are printed to stdout as they arrive, then the full response is returned.
    pub async fn generate_streaming(&self, query: &str, context: &str) -> Result<String, LlmError> {
        self.generate_internal(query, context, true).await
    }

    async fn generate_internal(&self, query: &str, context: &str, stream: bool) -> Result<String, LlmError> {
        let system_prompt = self.build_system_prompt();
        let user_prompt = self.build_user_prompt(query, context);

        match self.provider.as_str() {
            "openai" | "custom" => {
                if stream {
                    self.call_openai_streaming(&system_prompt, &user_prompt).await
                } else {
                    self.call_openai(&system_prompt, &user_prompt).await
                }
            }
            "anthropic" => {
                if stream {
                    self.call_anthropic_streaming(&system_prompt, &user_prompt).await
                } else {
                    self.call_anthropic(&system_prompt, &user_prompt).await
                }
            }
            "ollama" => {
                if stream {
                    self.call_ollama_streaming(&system_prompt, &user_prompt).await
                } else {
                    self.call_ollama(&system_prompt, &user_prompt).await
                }
            }
            _ => Err(LlmError::UnsupportedProvider {
                provider: self.provider.clone(),
            }),
        }
    }

    /// Build the system prompt for the LLM.
    fn build_system_prompt(&self) -> String {
        r#"You are Unfault, an AI assistant that helps developers understand the health of their codebase.

You analyze code quality findings from static analysis and provide actionable insights.

When answering questions:
- Be concise and direct: you are a SRE-in-their-pocket
- Focus on the most important issues first (Critical > High > Medium > Low)
- Group related findings when helpful
- Suggest specific actions to improve code quality
- Use technical language appropriate for developers
- You cannot offer to look further into it and it's a one-off response
- Be kind and professional

If the context doesn't contain relevant information, say so clearly rather than making assumptions."#.to_string()
    }

    /// Build the user prompt with query and context.
    fn build_user_prompt(&self, query: &str, context: &str) -> String {
        format!(
            r#"**User Question:** {}

**Analysis Context:**
{}

Based on this context, please answer the user's question about their codebase health."#,
            query, context
        )
    }

    /// Check if a model uses the newer OpenAI API format (max_completion_tokens).
    ///
    /// Newer models like gpt-4o, gpt-5, o1, etc. require `max_completion_tokens`
    /// instead of the deprecated `max_tokens` parameter.
    fn uses_new_token_param(model: &str) -> bool {
        let model_lower = model.to_lowercase();
        // gpt-4o, gpt-5, o1, o3, and any future models use the new parameter
        model_lower.contains("gpt-4o")
            || model_lower.contains("gpt-5")
            || model_lower.starts_with("o1")
            || model_lower.starts_with("o3")
            || model_lower.contains("chatgpt-4o")
    }

    /// Call OpenAI-compatible API.
    async fn call_openai(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/chat/completions", self.endpoint);
        let api_key = self.api_key.as_ref().ok_or_else(|| LlmError::MissingApiKey {
            env_var: "OPENAI_API_KEY".to_string(),
        })?;

        // Use max_completion_tokens for newer models, max_tokens for older ones
        // Reasoning models (gpt-5, o1, o3) use tokens for thinking + output, so need more
        let (max_tokens, max_completion_tokens, temperature) =
            if Self::uses_new_token_param(&self.model) {
                // Newer models: use max_completion_tokens
                let model_lower = self.model.to_lowercase();
                if model_lower.starts_with("o1")
                    || model_lower.starts_with("o3")
                    || model_lower.contains("gpt-5")
                {
                    // Reasoning models: need more tokens for thinking + output, no temperature
                    // gpt-5.1 uses reasoning_tokens + completion, so 16K allows generous thinking
                    (None, Some(16384), None)
                } else {
                    // gpt-4o and similar: standard limit with temperature
                    (None, Some(4096), Some(0.3))
                }
            } else {
                // Older models: use max_tokens
                (Some(4096), None, Some(0.3))
            };

        let request = OpenAIRequest {
            model: self.model.clone(),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: user_prompt.to_string(),
                },
            ],
            max_tokens,
            max_completion_tokens,
            temperature,
            stream: false,
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::Network {
                message: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            let error_msg = serde_json::from_str::<OpenAIErrorResponse>(&error_text)
                .map(|e| e.error.message)
                .unwrap_or(error_text);
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                message: error_msg,
            });
        }

        let response_text = response.text().await.map_err(|e| LlmError::Network {
            message: format!("Failed to read response body: {}", e),
        })?;

        if self.verbose {
            eprintln!("  {} Raw API response: {}", "DEBUG".yellow(), &response_text[..response_text.len().min(1000)]);
        }

        let openai_response: OpenAIResponse =
            serde_json::from_str(&response_text).map_err(|e| LlmError::ParseError {
                message: format!("Failed to parse OpenAI response: {}. Body: {}", e, &response_text[..response_text.len().min(500)]),
            })?;

        let content = openai_response
            .choices
            .first()
            .and_then(|c| c.message.content.clone());

        if self.verbose {
            eprintln!("  {} Extracted content: {:?}", "DEBUG".yellow(), content.as_ref().map(|s| &s[..s.len().min(200)]));
        }

        content.ok_or_else(|| LlmError::ParseError {
            message: format!(
                "No response content from model '{}'. Response: {}",
                self.model,
                &response_text[..response_text.len().min(500)]
            ),
        })
    }

    /// Call OpenAI-compatible API with streaming.
    async fn call_openai_streaming(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/chat/completions", self.endpoint);
        let api_key = self.api_key.as_ref().ok_or_else(|| LlmError::MissingApiKey {
            env_var: "OPENAI_API_KEY".to_string(),
        })?;

        let (max_tokens, max_completion_tokens, temperature) =
            if Self::uses_new_token_param(&self.model) {
                let model_lower = self.model.to_lowercase();
                if model_lower.starts_with("o1")
                    || model_lower.starts_with("o3")
                    || model_lower.contains("gpt-5")
                {
                    (None, Some(16384), None)
                } else {
                    (None, Some(4096), Some(0.3))
                }
            } else {
                (Some(4096), None, Some(0.3))
            };

        let request = OpenAIRequest {
            model: self.model.clone(),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: user_prompt.to_string(),
                },
            ],
            max_tokens,
            max_completion_tokens,
            temperature,
            stream: true,
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::Network {
                message: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            let error_msg = serde_json::from_str::<OpenAIErrorResponse>(&error_text)
                .map(|e| e.error.message)
                .unwrap_or(error_text);
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                message: error_msg,
            });
        }

        let mut full_content = String::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| LlmError::Network {
                message: format!("Stream error: {}", e),
            })?;

            let text = String::from_utf8_lossy(&chunk);
            
            // Parse SSE events (data: {...}\n\n format)
            for line in text.lines() {
                if line.starts_with("data: ") {
                    let json_str = &line[6..];
                    if json_str == "[DONE]" {
                        continue;
                    }
                    
                    if let Ok(stream_response) = serde_json::from_str::<OpenAIStreamResponse>(json_str) {
                        if let Some(choice) = stream_response.choices.first() {
                            if let Some(content) = &choice.delta.content {
                                print!("{}", content);
                                let _ = io::stdout().flush();
                                full_content.push_str(content);
                            }
                        }
                    }
                }
            }
        }

        println!(); // Final newline after streaming
        Ok(full_content)
    }

    /// Call Anthropic API.
    async fn call_anthropic(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/messages", self.endpoint);
        let api_key = self.api_key.as_ref().ok_or_else(|| LlmError::MissingApiKey {
            env_var: "ANTHROPIC_API_KEY".to_string(),
        })?;

        // Combine system and user prompt for Anthropic (system is passed differently)
        let combined_prompt = format!("{}\n\n{}", system_prompt, user_prompt);

        let request = AnthropicRequest {
            model: self.model.clone(),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: combined_prompt,
            }],
            max_tokens: 4096,
            stream: false,
        };

        let response = self
            .client
            .post(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::Network {
                message: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            let error_msg = serde_json::from_str::<AnthropicErrorResponse>(&error_text)
                .map(|e| e.error.message)
                .unwrap_or(error_text);
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                message: error_msg,
            });
        }

        let anthropic_response: AnthropicResponse = response.json().await.map_err(|e| {
            LlmError::ParseError {
                message: e.to_string(),
            }
        })?;

        anthropic_response
            .content
            .first()
            .map(|c| c.text.clone())
            .ok_or_else(|| LlmError::ParseError {
                message: "No response content".to_string(),
            })
    }

    /// Call Anthropic API with streaming.
    async fn call_anthropic_streaming(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/messages", self.endpoint);
        let api_key = self.api_key.as_ref().ok_or_else(|| LlmError::MissingApiKey {
            env_var: "ANTHROPIC_API_KEY".to_string(),
        })?;

        let combined_prompt = format!("{}\n\n{}", system_prompt, user_prompt);

        let request = AnthropicRequest {
            model: self.model.clone(),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: combined_prompt,
            }],
            max_tokens: 4096,
            stream: true,
        };

        let response = self
            .client
            .post(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::Network {
                message: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            let error_msg = serde_json::from_str::<AnthropicErrorResponse>(&error_text)
                .map(|e| e.error.message)
                .unwrap_or(error_text);
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                message: error_msg,
            });
        }

        let mut full_content = String::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| LlmError::Network {
                message: format!("Stream error: {}", e),
            })?;

            let text = String::from_utf8_lossy(&chunk);
            
            // Parse SSE events (event: type\ndata: {...}\n\n format)
            for line in text.lines() {
                if line.starts_with("data: ") {
                    let json_str = &line[6..];
                    
                    if let Ok(event) = serde_json::from_str::<AnthropicStreamEvent>(json_str) {
                        if event.event_type == "content_block_delta" {
                            if let Some(delta) = &event.delta {
                                if let Some(text) = &delta.text {
                                    print!("{}", text);
                                    let _ = io::stdout().flush();
                                    full_content.push_str(text);
                                }
                            }
                        }
                    }
                }
            }
        }

        println!(); // Final newline after streaming
        Ok(full_content)
    }

    /// Call Ollama API.
    async fn call_ollama(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/api/chat", self.endpoint);

        let request = OllamaRequest {
            model: self.model.clone(),
            messages: vec![
                OllamaMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                OllamaMessage {
                    role: "user".to_string(),
                    content: user_prompt.to_string(),
                },
            ],
            stream: false,
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::Network {
                message: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let ollama_response: OllamaResponse = response.json().await.map_err(|e| {
            LlmError::ParseError {
                message: e.to_string(),
            }
        })?;

        Ok(ollama_response.message.content)
    }

    /// Call Ollama API with streaming.
    async fn call_ollama_streaming(&self, system_prompt: &str, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/api/chat", self.endpoint);

        let request = OllamaRequest {
            model: self.model.clone(),
            messages: vec![
                OllamaMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                OllamaMessage {
                    role: "user".to_string(),
                    content: user_prompt.to_string(),
                },
            ],
            stream: true,
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::Network {
                message: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let mut full_content = String::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| LlmError::Network {
                message: format!("Stream error: {}", e),
            })?;

            let text = String::from_utf8_lossy(&chunk);
            
            // Ollama streams newline-delimited JSON
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                
                // Parse each line as a JSON object
                #[derive(Deserialize)]
                struct OllamaStreamChunk {
                    message: Option<OllamaMessageResponse>,
                }
                
                if let Ok(chunk) = serde_json::from_str::<OllamaStreamChunk>(line) {
                    if let Some(message) = chunk.message {
                        print!("{}", message.content);
                        let _ = io::stdout().flush();
                        full_content.push_str(&message.content);
                    }
                }
            }
        }

        println!(); // Final newline after streaming
        Ok(full_content)
    }
}

/// Build a rich context string from RAG response for LLM consumption.
pub fn build_llm_context(
    context_summary: &str,
    sessions: &[crate::api::rag::RAGSessionContext],
    findings: &[crate::api::rag::RAGFindingContext],
) -> String {
    let mut parts = vec![context_summary.to_string()];

    if !sessions.is_empty() {
        parts.push("\n### Session Details:".to_string());
        for session in sessions {
            let workspace = session.workspace_label.as_deref().unwrap_or("Unknown");
            parts.push(format!(
                "- **{}**: {} findings ({}% relevance)",
                workspace,
                session.total_findings,
                (session.similarity * 100.0).round() as i32
            ));

            if !session.dimension_counts.is_empty() {
                let dims: Vec<String> = session
                    .dimension_counts
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                parts.push(format!("  Dimensions: {}", dims.join(", ")));
            }

            if !session.severity_counts.is_empty() {
                let sevs: Vec<String> = session
                    .severity_counts
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                parts.push(format!("  Severities: {}", sevs.join(", ")));
            }
        }
    }

    if !findings.is_empty() {
        parts.push("\n### Top Findings:".to_string());
        for finding in findings {
            let rule = finding.rule_id.as_deref().unwrap_or("unknown");
            let severity = finding.severity.as_deref().unwrap_or("unknown");
            let dimension = finding.dimension.as_deref().unwrap_or("unknown");

            let location = match (&finding.file_path, finding.line) {
                (Some(path), Some(line)) => format!(" at {}:{}", path, line),
                (Some(path), None) => format!(" in {}", path),
                _ => String::new(),
            };

            parts.push(format!(
                "- **{}** [{}] ({}){} - {}% relevance",
                rule,
                severity,
                dimension,
                location,
                (finding.similarity * 100.0).round() as i32
            ));
        }
    }

    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_system_prompt() {
        let config = LlmConfig::openai("gpt-4");
        // Skip API key check for test
        let client = LlmClient {
            client: reqwest::Client::new(),
            provider: config.provider,
            endpoint: config.endpoint,
            model: config.model,
            api_key: Some("test-key".to_string()),
            verbose: false,
        };
        let prompt = client.build_system_prompt();
        assert!(prompt.contains("Unfault"));
        assert!(prompt.contains("code"));
    }

    #[test]
    fn test_build_user_prompt() {
        let config = LlmConfig::openai("gpt-4");
        let client = LlmClient {
            client: reqwest::Client::new(),
            provider: config.provider,
            endpoint: config.endpoint,
            model: config.model,
            api_key: Some("test-key".to_string()),
            verbose: false,
        };
        let prompt = client.build_user_prompt("How is my service?", "Context here");
        assert!(prompt.contains("How is my service?"));
        assert!(prompt.contains("Context here"));
    }

    #[test]
    fn test_llm_error_display() {
        let err = LlmError::MissingApiKey {
            env_var: "OPENAI_API_KEY".to_string(),
        };
        assert!(err.to_string().contains("OPENAI_API_KEY"));

        let err = LlmError::Network {
            message: "connection refused".to_string(),
        };
        assert!(err.to_string().contains("connection refused"));

        let err = LlmError::ApiError {
            status: 429,
            message: "rate limited".to_string(),
        };
        assert!(err.to_string().contains("429"));

        let err = LlmError::UnsupportedProvider {
            provider: "unknown".to_string(),
        };
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_build_llm_context_empty() {
        let context = build_llm_context("No findings", &[], &[]);
        assert_eq!(context, "No findings");
    }

    #[test]
    fn test_build_llm_context_with_sessions() {
        use crate::api::rag::RAGSessionContext;

        let sessions = vec![RAGSessionContext {
            session_id: "test".to_string(),
            workspace_label: Some("my-service".to_string()),
            created_at: None,
            similarity: 0.85,
            total_findings: 10,
            dimension_counts: [("Stability".to_string(), 5)].into_iter().collect(),
            severity_counts: [("High".to_string(), 3)].into_iter().collect(),
        }];

        let context = build_llm_context("Summary", &sessions, &[]);
        assert!(context.contains("my-service"));
        assert!(context.contains("10 findings"));
        assert!(context.contains("Stability"));
    }

    #[test]
    fn test_build_llm_context_with_findings() {
        use crate::api::rag::RAGFindingContext;

        let findings = vec![RAGFindingContext {
            finding_id: "test".to_string(),
            rule_id: Some("http.timeout".to_string()),
            dimension: Some("Stability".to_string()),
            severity: Some("High".to_string()),
            file_path: Some("api/client.py".to_string()),
            line: Some(42),
            similarity: 0.78,
        }];

        let context = build_llm_context("Summary", &[], &findings);
        assert!(context.contains("http.timeout"));
        assert!(context.contains("High"));
        assert!(context.contains("api/client.py:42"));
    }
}
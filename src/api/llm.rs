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
// Streaming Line Wrapper
// =============================================================================

/// Maximum width for terminal output
const MAX_LINE_WIDTH: usize = 80;

/// A streaming line wrapper that buffers text and prints with line wrapping.
///
/// This handles streaming tokens (which may be partial words) by buffering
/// until whitespace is encountered, then wrapping appropriately.
struct StreamingLineWrapper {
    /// Current column position (0-indexed)
    column: usize,
    /// Buffer for the current word (tokens until whitespace)
    word_buffer: String,
}

impl StreamingLineWrapper {
    fn new() -> Self {
        Self {
            column: 0,
            word_buffer: String::new(),
        }
    }

    /// Process incoming text chunk and print with line wrapping
    fn write(&mut self, text: &str) {
        for ch in text.chars() {
            if ch == '\n' {
                // Flush current word buffer and print newline
                self.flush_word();
                println!();
                self.column = 0;
            } else if ch.is_whitespace() {
                // Flush word buffer, then handle the space
                self.flush_word();
                // Only print space if we're not at the start of a line
                if self.column > 0 && self.column < MAX_LINE_WIDTH {
                    print!(" ");
                    self.column += 1;
                }
            } else {
                // Accumulate non-whitespace characters
                self.word_buffer.push(ch);
            }
        }
        let _ = io::stdout().flush();
    }

    /// Flush the word buffer, wrapping to a new line if needed
    fn flush_word(&mut self) {
        if self.word_buffer.is_empty() {
            return;
        }

        let word_len = self.word_buffer.chars().count();

        // Check if we need to wrap
        if self.column > 0 && self.column + word_len > MAX_LINE_WIDTH {
            // Wrap to the next line
            println!();
            self.column = 0;
        }

        // Print the word
        print!("{}", self.word_buffer);
        self.column += word_len;
        self.word_buffer.clear();
    }

    /// Finish streaming and flush any remaining content
    fn finish(&mut self) {
        self.flush_word();
        // Print final newline
        println!();
        let _ = io::stdout().flush();
    }
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
                let env_var = config
                    .api_key_env
                    .clone()
                    .unwrap_or_else(|| "API_KEY".to_string());
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

    async fn generate_internal(
        &self,
        query: &str,
        context: &str,
        stream: bool,
    ) -> Result<String, LlmError> {
        let system_prompt = self.build_system_prompt();
        let user_prompt = self.build_user_prompt(query, context);

        match self.provider.as_str() {
            "openai" | "custom" => {
                if stream {
                    self.call_openai_streaming(&system_prompt, &user_prompt)
                        .await
                } else {
                    self.call_openai(&system_prompt, &user_prompt).await
                }
            }
            "anthropic" => {
                if stream {
                    self.call_anthropic_streaming(&system_prompt, &user_prompt)
                        .await
                } else {
                    self.call_anthropic(&system_prompt, &user_prompt).await
                }
            }
            "ollama" => {
                if stream {
                    self.call_ollama_streaming(&system_prompt, &user_prompt)
                        .await
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
        r#"You are Unfault — a pragmatic engineering teammate.

Your job is to help the developer understand what this workspace is, how it is structured, and how it behaves.
You may be given structured context (workspace overview, routes/flows, dependencies, cross-workspace links) and sometimes findings from reviews.

Guidelines:
- Answer the user’s question first, in a natural colleague voice (1–3 sentences).
- Prefer telling the story from structure and behavior (languages, frameworks, entrypoints, key modules, routes, call paths, dependencies).
- Use findings only when (a) the user asked about issues/risks, or (b) they are directly relevant to the question.
- Be grounded: only claim what the provided context supports. If you’re unsure, say what’s missing.
- Cite concrete anchors when available: file paths, endpoints, symbols.
- If blocked by a missing target, ask one clarifying question and also provide a best-effort answer with explicit assumptions.
- Keep it tight. Use short bullets only when they improve scanability.

Never invent code. Do not claim you ran commands or opened files beyond the provided context."#
            .to_string()
    }

    /// Build the user prompt with query and context.
    fn build_user_prompt(&self, query: &str, context: &str) -> String {
        format!(
            r#"User question:
{}

Context (ground truth, may be incomplete):
{}

Task:
Answer the user’s question using the context. Prefer workspace structure/behavior over findings unless the user asked for issues.
If helpful, end with 1–2 suggested follow-up questions the user can ask next."#,
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
    async fn call_openai(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, LlmError> {
        let url = format!("{}/chat/completions", self.endpoint);
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| LlmError::MissingApiKey {
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
            eprintln!(
                "  {} Raw API response: {}",
                "DEBUG".yellow(),
                &response_text[..response_text.len().min(1000)]
            );
        }

        let openai_response: OpenAIResponse =
            serde_json::from_str(&response_text).map_err(|e| LlmError::ParseError {
                message: format!(
                    "Failed to parse OpenAI response: {}. Body: {}",
                    e,
                    &response_text[..response_text.len().min(500)]
                ),
            })?;

        let content = openai_response
            .choices
            .first()
            .and_then(|c| c.message.content.clone());

        if self.verbose {
            eprintln!(
                "  {} Extracted content: {:?}",
                "DEBUG".yellow(),
                content.as_ref().map(|s| &s[..s.len().min(200)])
            );
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
    async fn call_openai_streaming(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, LlmError> {
        let url = format!("{}/chat/completions", self.endpoint);
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| LlmError::MissingApiKey {
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
        let mut wrapper = StreamingLineWrapper::new();

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

                    if let Ok(stream_response) =
                        serde_json::from_str::<OpenAIStreamResponse>(json_str)
                    {
                        if let Some(choice) = stream_response.choices.first() {
                            if let Some(content) = &choice.delta.content {
                                wrapper.write(content);
                                full_content.push_str(content);
                            }
                        }
                    }
                }
            }
        }

        wrapper.finish();
        Ok(full_content)
    }

    /// Call Anthropic API.
    async fn call_anthropic(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, LlmError> {
        let url = format!("{}/messages", self.endpoint);
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| LlmError::MissingApiKey {
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

        let anthropic_response: AnthropicResponse =
            response.json().await.map_err(|e| LlmError::ParseError {
                message: e.to_string(),
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
    async fn call_anthropic_streaming(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, LlmError> {
        let url = format!("{}/messages", self.endpoint);
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| LlmError::MissingApiKey {
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
        let mut wrapper = StreamingLineWrapper::new();

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
                                    wrapper.write(text);
                                    full_content.push_str(text);
                                }
                            }
                        }
                    }
                }
            }
        }

        wrapper.finish();
        Ok(full_content)
    }

    /// Call Ollama API.
    async fn call_ollama(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, LlmError> {
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

        let ollama_response: OllamaResponse =
            response.json().await.map_err(|e| LlmError::ParseError {
                message: e.to_string(),
            })?;

        Ok(ollama_response.message.content)
    }

    /// Call Ollama API with streaming.
    async fn call_ollama_streaming(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, LlmError> {
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
        let mut wrapper = StreamingLineWrapper::new();

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
                        wrapper.write(&message.content);
                        full_content.push_str(&message.content);
                    }
                }
            }
        }

        wrapper.finish();
        Ok(full_content)
    }
}

/// Build a rich context string from a RAG response for LLM consumption.
pub fn build_llm_context(response: &crate::api::rag::RAGQueryResponse) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(ctx) = &response.workspace_context {
        parts.push("## Workspace".to_string());
        parts.push(ctx.summary.clone());

        if !ctx.entrypoints.is_empty() {
            parts.push(format!("Entrypoints: {}", ctx.entrypoints.join(", ")));
        }

        if !ctx.central_files.is_empty() {
            let top = ctx
                .central_files
                .iter()
                .take(5)
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("Hotspots: {}", top));
        }

        if !ctx.top_dependencies.is_empty() {
            let deps = ctx
                .top_dependencies
                .iter()
                .take(10)
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("Dependencies: {}", deps));
        }

        if !ctx.remote_servers.is_empty() {
            parts.push(format!(
                "Outbound remotes: {}",
                ctx.remote_servers.join(", ")
            ));
        }
    }

    if let Some(flow) = &response.flow_context {
        if !flow.paths.is_empty() {
            parts.push("\n## Flow".to_string());
            if let Some(q) = &flow.query {
                parts.push(format!("Query: {}", q));
            }
            for (i, path) in flow.paths.iter().take(5).enumerate() {
                let s = path
                    .iter()
                    .map(|n| n.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                parts.push(format!("- Path {}: {}", i + 1, s));
            }
        }
    }

    if !response.context_summary.trim().is_empty() {
        parts.push("\n## Retrieved context".to_string());
        parts.push(response.context_summary.clone());
    }

    let sessions = &response.sessions;
    let findings = &response.findings;

    if !sessions.is_empty() {
        parts.push("\n## Sessions".to_string());
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
        parts.push("\n## Findings".to_string());
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

pub fn build_llm_context_with_local_code(
    response: &crate::api::rag::RAGQueryResponse,
    workspace_path: Option<&std::path::Path>,
    graph_data: Option<&crate::api::rag::ClientGraphData>,
) -> String {
    let mut parts: Vec<String> = vec![build_llm_context(response)];

    let Some(root) = workspace_path else {
        return parts.join("\n");
    };

    let mut candidate_paths: Vec<String> = Vec::new();
    if let Some(ctx) = &response.workspace_context {
        candidate_paths.extend(ctx.entrypoints.iter().take(3).cloned());
        candidate_paths.extend(ctx.central_files.iter().take(3).map(|f| f.path.clone()));
    }
    if let Some(flow) = &response.flow_context {
        for p in &flow.paths {
            for n in p.iter().take(6) {
                if let Some(fp) = &n.path {
                    candidate_paths.push(fp.clone());
                }
            }
        }
    }
    candidate_paths.sort();
    candidate_paths.dedup();
    candidate_paths.truncate(5);

    if candidate_paths.is_empty() {
        return parts.join("\n");
    }

    let mut excerpts: Vec<String> = Vec::new();
    for rel in candidate_paths {
        let abs = root.join(&rel);
        let Ok(text) = std::fs::read_to_string(&abs) else {
            continue;
        };

        // Keep context tight.
        let mut kept: Vec<String> = Vec::new();
        let mut lines = text.lines().enumerate().peekable();
        while let Some((idx, line)) = lines.next() {
            let l = line.trim_start();

            let is_route = l.starts_with("@app.")
                || l.starts_with("@router.")
                || l.starts_with("@app.get(")
                || l.starts_with("@app.post(")
                || l.starts_with("@app.put(")
                || l.starts_with("@app.patch(")
                || l.starts_with("@app.delete(");

            let is_model = l.starts_with("class ") && l.contains("BaseModel") && l.ends_with(":");
            let is_http =
                l.contains("httpx.") || l.contains("client.get") || l.contains("client.post");
            let is_env = l.contains("os.getenv")
                || l.contains("_URL")
                || l.contains("_HOST")
                || l.contains("_PORT");

            if !(is_route || is_model || is_http || is_env) {
                continue;
            }

            // Capture a small window around the match.
            let start = idx.saturating_sub(0);
            let mut buf = Vec::new();
            buf.push(format!("{:4} | {}", start + 1, line));

            // For decorators and class defs, capture a few following lines.
            let follow = if is_model { 20 } else { 6 };
            for _ in 0..follow {
                let Some((j, nxt)) = lines.peek().cloned() else {
                    break;
                };
                let nxt_trim = nxt.trim();
                if nxt_trim.is_empty() {
                    break;
                }
                // Stop at next top-level def/class after a model block.
                if is_model
                    && (nxt.starts_with("class ")
                        || nxt.starts_with("def ")
                        || nxt.starts_with("@"))
                {
                    break;
                }
                let _ = lines.next();
                buf.push(format!("{:4} | {}", j + 1, nxt));
            }

            kept.extend(buf);
            if kept.len() > 120 {
                break;
            }
        }

        if kept.is_empty() {
            continue;
        }

        excerpts.push(format!(
            "\n## Code excerpts ({})\n```\n{}\n```",
            rel,
            kept.join("\n")
        ));
    }

    if !excerpts.is_empty() {
        parts.push("\n# Local code context".to_string());
        parts.extend(excerpts);
    }

    // Optionally include a compact route list from local graph, if the question
    // asks for routes but the response doesn't already contain enumerate context.
    if response.enumerate_context.is_none() {
        if let Some(gd) = graph_data {
            let ql = response.query.to_lowercase();
            if ql.contains("route") || ql.contains("endpoint") {
                let mut routes: Vec<String> = Vec::new();
                for f in &gd.functions {
                    let hm = f.get("http_method").and_then(|v| v.as_str()).unwrap_or("");
                    let hp = f.get("http_path").and_then(|v| v.as_str()).unwrap_or("");
                    if !hm.is_empty() && !hp.is_empty() {
                        routes.push(format!("{} {}", hm.to_uppercase(), hp));
                    }
                }
                routes.sort();
                routes.dedup();
                if !routes.is_empty() {
                    parts.push("\n## Routes (from local graph)".to_string());
                    for r in routes.into_iter().take(20) {
                        parts.push(format!("- {}", r));
                    }
                }
            }
        }
    }

    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::rag::RAGQueryResponse;

    fn base_response(context_summary: &str) -> RAGQueryResponse {
        RAGQueryResponse {
            query: "q".to_string(),
            sessions: vec![],
            findings: vec![],
            sources: vec![],
            context_summary: context_summary.to_string(),
            topic_label: None,
            graph_context: None,
            flow_context: None,
            slo_context: None,
            enumerate_context: None,
            graph_stats: None,
            workspace_context: None,
            routing_confidence: None,
            hint: None,
            disambiguation: None,
        }
    }

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
        assert!(prompt.contains("engineering teammate"));
        assert!(!prompt.contains("SRE-in-their-pocket"));
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
        assert!(prompt.contains("Task:"));
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
        let response = base_response("No context");
        let context = build_llm_context(&response);
        assert!(context.contains("No context"));
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

        let mut response = base_response("Summary");
        response.sessions = sessions;
        let context = build_llm_context(&response);
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

        let mut response = base_response("Summary");
        response.findings = findings;
        let context = build_llm_context(&response);
        assert!(context.contains("http.timeout"));
        assert!(context.contains("High"));
        assert!(context.contains("api/client.py:42"));
    }

    #[test]
    fn test_build_llm_context_with_local_code_no_workspace_path_is_ok() {
        let response = base_response("No context");
        let context = build_llm_context_with_local_code(&response, None, None);
        assert!(context.contains("No context"));
    }
}

//! Agent Fingerprinting Module
//!
//! Automatically identifies AI agents, frameworks, and LLM providers
//! from intercepted traffic patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// Detected LLM provider
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LlmProvider {
    OpenAI,
    Anthropic,
    Google,
    Azure,
    Bedrock,
    Cohere,
    Mistral,
    Ollama,
    Together,
    Groq,
    Unknown(String),
}

impl LlmProvider {
    pub fn from_hostname(host: &str) -> Self {
        let host_lower = host.to_lowercase();

        if host_lower.contains("api.openai.com") {
            LlmProvider::OpenAI
        } else if host_lower.contains("api.anthropic.com") {
            LlmProvider::Anthropic
        } else if host_lower.contains("generativelanguage.googleapis.com")
            || host_lower.contains("aiplatform.googleapis.com")
        {
            LlmProvider::Google
        } else if host_lower.contains("openai.azure.com") {
            LlmProvider::Azure
        } else if host_lower.contains("bedrock") && host_lower.contains("amazonaws.com") {
            LlmProvider::Bedrock
        } else if host_lower.contains("api.cohere.ai") {
            LlmProvider::Cohere
        } else if host_lower.contains("api.mistral.ai") {
            LlmProvider::Mistral
        } else if host_lower.contains("localhost:11434") || host_lower.contains("ollama") {
            LlmProvider::Ollama
        } else if host_lower.contains("api.together.xyz") {
            LlmProvider::Together
        } else if host_lower.contains("api.groq.com") {
            LlmProvider::Groq
        } else {
            LlmProvider::Unknown(host.to_string())
        }
    }

    pub fn name(&self) -> &str {
        match self {
            LlmProvider::OpenAI => "OpenAI",
            LlmProvider::Anthropic => "Anthropic",
            LlmProvider::Google => "Google AI",
            LlmProvider::Azure => "Azure OpenAI",
            LlmProvider::Bedrock => "AWS Bedrock",
            LlmProvider::Cohere => "Cohere",
            LlmProvider::Mistral => "Mistral AI",
            LlmProvider::Ollama => "Ollama (Local)",
            LlmProvider::Together => "Together AI",
            LlmProvider::Groq => "Groq",
            LlmProvider::Unknown(_) => "Unknown",
        }
    }
}

/// Detected agent framework
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentFramework {
    // AI Coding Assistants
    ClaudeCode,
    CopilotCli,
    Cursor,
    Windsurf,
    Aider,

    // Python Frameworks
    LangChain,
    LlamaIndex,
    CrewAI,
    AutoGen,
    Haystack,

    // SDKs
    OpenAIPython,
    OpenAINode,
    AnthropicPython,
    AnthropicNode,

    // Other
    CustomAgent,
    Unknown(String),
}

impl AgentFramework {
    pub fn name(&self) -> &str {
        match self {
            AgentFramework::ClaudeCode => "Claude Code",
            AgentFramework::CopilotCli => "GitHub Copilot CLI",
            AgentFramework::Cursor => "Cursor IDE",
            AgentFramework::Windsurf => "Windsurf",
            AgentFramework::Aider => "Aider",
            AgentFramework::LangChain => "LangChain",
            AgentFramework::LlamaIndex => "LlamaIndex",
            AgentFramework::CrewAI => "CrewAI",
            AgentFramework::AutoGen => "AutoGen",
            AgentFramework::Haystack => "Haystack",
            AgentFramework::OpenAIPython => "OpenAI Python SDK",
            AgentFramework::OpenAINode => "OpenAI Node.js SDK",
            AgentFramework::AnthropicPython => "Anthropic Python SDK",
            AgentFramework::AnthropicNode => "Anthropic Node.js SDK",
            AgentFramework::CustomAgent => "Custom Agent",
            AgentFramework::Unknown(name) => name.as_str(),
        }
    }

    pub fn category(&self) -> &str {
        match self {
            AgentFramework::ClaudeCode
            | AgentFramework::CopilotCli
            | AgentFramework::Cursor
            | AgentFramework::Windsurf
            | AgentFramework::Aider => "AI Coding Assistant",

            AgentFramework::LangChain
            | AgentFramework::LlamaIndex
            | AgentFramework::CrewAI
            | AgentFramework::AutoGen
            | AgentFramework::Haystack => "Agent Framework",

            AgentFramework::OpenAIPython
            | AgentFramework::OpenAINode
            | AgentFramework::AnthropicPython
            | AgentFramework::AnthropicNode => "SDK",

            _ => "Other",
        }
    }
}

/// Session information for tracking conversations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session/conversation ID
    pub session_id: String,
    /// Session type (conversation, run, trace, etc.)
    pub session_type: SessionType,
    /// Optional human-friendly session/conversation name
    pub session_name: Option<String>,
    /// First seen timestamp
    pub first_seen: SystemTime,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Request count in this session
    pub request_count: u64,
    /// Models used in this session
    pub models: Vec<String>,
    /// Total tokens observed for this session
    pub total_tokens: u64,
    /// Total tool calls observed for this session
    pub total_tool_calls: u64,
}

/// Type of session identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionType {
    /// Claude Code conversation
    ClaudeConversation,
    /// LangChain run ID
    LangChainRun,
    /// LangChain trace ID
    LangChainTrace,
    /// Generic request/trace ID
    TraceId,
    /// OpenAI request ID
    OpenAIRequest,
    /// Anthropic request ID
    AnthropicRequest,
    /// Custom session ID
    Custom(String),
}

impl SessionType {
    pub fn name(&self) -> &str {
        match self {
            SessionType::ClaudeConversation => "Claude Conversation",
            SessionType::LangChainRun => "LangChain Run",
            SessionType::LangChainTrace => "LangChain Trace",
            SessionType::TraceId => "Trace ID",
            SessionType::OpenAIRequest => "OpenAI Request",
            SessionType::AnthropicRequest => "Anthropic Request",
            SessionType::Custom(name) => name.as_str(),
        }
    }
}

/// Fingerprint of an identified agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFingerprint {
    /// Unique identifier for this agent instance
    pub id: String,
    /// Detected framework
    pub framework: AgentFramework,
    /// LLM providers used
    pub providers: Vec<LlmProvider>,
    /// Process name (from eBPF)
    pub process_name: Option<String>,
    /// Process ID (from eBPF)
    pub pid: Option<u32>,
    /// User-Agent string
    pub user_agent: Option<String>,
    /// Custom headers detected
    pub custom_headers: HashMap<String, String>,
    /// Models used
    pub models: Vec<String>,
    /// Active sessions/conversations
    pub sessions: HashMap<String, SessionInfo>,
    /// First seen timestamp
    pub first_seen: SystemTime,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Total requests
    pub request_count: u64,
    /// Total tokens (estimated)
    pub total_tokens: u64,
    /// Total tool calls observed
    pub total_tool_calls: u64,
    /// Estimated cost
    pub estimated_cost: f64,
    /// Risk score (0-100)
    pub risk_score: u32,
    /// Security events
    pub security_events: Vec<SecurityEvent>,
}

/// Security event associated with an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub severity: String,
    pub timestamp: SystemTime,
    pub details: String,
}

/// Agent Fingerprinter - identifies agents from traffic
pub struct AgentFingerprinter {
    /// Known agents by fingerprint ID
    agents: Arc<RwLock<HashMap<String, AgentFingerprint>>>,
    /// Process name to agent mapping
    process_map: Arc<RwLock<HashMap<u32, String>>>,
}

#[derive(Debug, Clone)]
struct ExtractedSession {
    session_id: String,
    session_type: SessionType,
    session_name: Option<String>,
}

impl AgentFingerprinter {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            process_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Analyze request and fingerprint the agent
    pub fn analyze_request(&self, request: &RequestInfo) -> AgentFingerprint {
        // Generate fingerprint ID from available signals
        let fingerprint_id = self.generate_fingerprint_id(request);

        // Detect framework from various signals
        let framework = self.detect_framework(request);

        // Detect provider from hostname
        let provider = LlmProvider::from_hostname(&request.hostname);

        // Detect model from request body
        let model = self.extract_model(&request.body);

        // Extract session information
        let sessions = self.extract_sessions(request);

        // Get or create fingerprint
        let mut agents = self.agents.write().unwrap_or_else(|e| e.into_inner());

        let fingerprint =
            agents
                .entry(fingerprint_id.clone())
                .or_insert_with(|| AgentFingerprint {
                    id: fingerprint_id.clone(),
                    framework: framework.clone(),
                    providers: vec![],
                    process_name: request.process_name.clone(),
                    pid: request.pid,
                    user_agent: request.user_agent.clone(),
                    custom_headers: HashMap::new(),
                    models: vec![],
                    sessions: HashMap::new(),
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    request_count: 0,
                    total_tokens: 0,
                    total_tool_calls: 0,
                    estimated_cost: 0.0,
                    risk_score: 0,
                    security_events: vec![],
                });

        // Update fingerprint
        fingerprint.last_seen = SystemTime::now();
        fingerprint.request_count += 1;

        if !fingerprint.providers.contains(&provider) {
            fingerprint.providers.push(provider);
        }

        if let Some(ref m) = model {
            if !fingerprint.models.contains(m) {
                fingerprint.models.push(m.clone());
            }
        }

        // Update session tracking
        for extracted in sessions {
            let session_id = extracted.session_id;
            let session_type = extracted.session_type;
            let session_name = extracted.session_name;
            let session = fingerprint
                .sessions
                .entry(session_id.clone())
                .or_insert_with(|| SessionInfo {
                    session_id: session_id.clone(),
                    session_type,
                    session_name: session_name.clone(),
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    request_count: 0,
                    models: vec![],
                    total_tokens: 0,
                    total_tool_calls: 0,
                });
            if session.session_name.is_none() && session_name.is_some() {
                session.session_name = session_name.clone();
            }
            session.last_seen = SystemTime::now();
            session.request_count += 1;
            if let Some(ref m) = model {
                if !session.models.contains(m) {
                    session.models.push(m.clone());
                }
            }
        }

        // Store custom headers
        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();
            if key_lower.starts_with("x-")
                || key_lower.contains("langchain")
                || key_lower.contains("openai")
                || key_lower.contains("anthropic")
            {
                fingerprint
                    .custom_headers
                    .insert(key.clone(), value.clone());
            }
        }

        // Update process map
        if let Some(pid) = request.pid {
            let mut pmap = self.process_map.write().unwrap_or_else(|e| e.into_inner());
            pmap.insert(pid, fingerprint_id.clone());
        }

        fingerprint.clone()
    }

    /// Generate a unique fingerprint ID from request signals
    fn generate_fingerprint_id(&self, request: &RequestInfo) -> String {
        if let Some(exe_path) = &request.exe_path {
            let exe_lower = exe_path.to_ascii_lowercase();
            if exe_lower.contains("copilot") {
                if let Some(pid) = request.pid {
                    return format!("copilot:{}", pid);
                }
                return "copilot:unknown".to_string();
            }
        }

        // Prefer process-based ID if available (from eBPF)
        if let (Some(pid), Some(name)) = (&request.pid, &request.process_name) {
            return format!("{}:{}", name, pid);
        }

        // Fall back to User-Agent based ID
        if let Some(ua) = &request.user_agent {
            let ua_hash = self.hash_user_agent(ua);
            return format!("ua:{}", ua_hash);
        }

        // Last resort: session-based
        format!("session:{}", rand_id())
    }

    /// Detect framework from request signals
    fn detect_framework(&self, request: &RequestInfo) -> AgentFramework {
        if self.looks_like_copilot(request) {
            return AgentFramework::CopilotCli;
        }

        // Check process name first (most reliable from eBPF)
        if let Some(process) = &request.process_name {
            let process_lower = process.to_lowercase();

            if process_lower.contains("claude") {
                return AgentFramework::ClaudeCode;
            }
            if process_lower == "gh" || process_lower.contains("copilot") {
                return AgentFramework::CopilotCli;
            }
            if process_lower.contains("cursor") {
                return AgentFramework::Cursor;
            }
            if process_lower.contains("windsurf") {
                return AgentFramework::Windsurf;
            }
            if process_lower.contains("aider") {
                return AgentFramework::Aider;
            }
        }

        // Check User-Agent
        if let Some(ua) = &request.user_agent {
            let ua_lower = ua.to_lowercase();

            // OpenAI SDKs
            if ua_lower.contains("openai-python") {
                return AgentFramework::OpenAIPython;
            }
            if ua_lower.contains("openai-node") || ua_lower.contains("openai/") {
                return AgentFramework::OpenAINode;
            }

            // Anthropic SDKs
            if ua_lower.contains("anthropic-python") || ua_lower.contains("claude-") {
                return AgentFramework::AnthropicPython;
            }
            if ua_lower.contains("anthropic-typescript") || ua_lower.contains("@anthropic-ai") {
                return AgentFramework::AnthropicNode;
            }

            // Frameworks often modify User-Agent
            if ua_lower.contains("langchain") {
                return AgentFramework::LangChain;
            }
            if ua_lower.contains("llamaindex") || ua_lower.contains("llama-index") {
                return AgentFramework::LlamaIndex;
            }
        }

        // Check custom headers
        for key in request.headers.keys() {
            let key_lower = key.to_lowercase();

            if key_lower.contains("langchain") || key_lower == "x-langchain-request" {
                return AgentFramework::LangChain;
            }
            if key_lower.contains("llamaindex") {
                return AgentFramework::LlamaIndex;
            }
        }

        // Check request body for framework patterns
        if let Some(body) = &request.body {
            let body_lower = body.to_lowercase();

            // CrewAI often includes specific patterns
            if body_lower.contains("crewai") || body_lower.contains("crew_agent") {
                return AgentFramework::CrewAI;
            }

            // AutoGen patterns
            if body_lower.contains("autogen") || body_lower.contains("assistant_agent") {
                return AgentFramework::AutoGen;
            }

            // LangChain patterns in prompts
            if body_lower.contains("langchain") || body_lower.contains("lcel") {
                return AgentFramework::LangChain;
            }
        }

        // Default based on provider
        let provider = LlmProvider::from_hostname(&request.hostname);
        match provider {
            LlmProvider::OpenAI | LlmProvider::Azure => AgentFramework::OpenAIPython,
            LlmProvider::Anthropic => AgentFramework::AnthropicPython,
            _ => AgentFramework::Unknown("Unknown".to_string()),
        }
    }

    fn looks_like_copilot(&self, request: &RequestInfo) -> bool {
        if let Some(process) = &request.process_name {
            let process_lower = process.to_ascii_lowercase();
            if process_lower.contains("copilot") {
                return true;
            }
        }

        if let Some(exe_path) = &request.exe_path {
            let exe_lower = exe_path.to_ascii_lowercase();
            if exe_lower.contains("copilot") {
                return true;
            }
        }

        if let Some(ua) = &request.user_agent {
            let ua_lower = ua.to_ascii_lowercase();
            if ua_lower.contains("copilot") || ua_lower.contains("github-copilot") {
                return true;
            }
        }

        let Some(pid) = request.pid else {
            return false;
        };

        let process_name = request
            .process_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !(process_name.contains("mainthread")
            || process_name.contains("node")
            || process_name.is_empty())
        {
            return false;
        }

        let exe_link = format!("/proc/{}/exe", pid);
        let Ok(exe_path) = std::fs::read_link(exe_link) else {
            return false;
        };
        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if exe_name == "copilot"
            || exe_path
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("copilot")
        {
            return true;
        }

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let Ok(cmdline_bytes) = std::fs::read(cmdline_path) else {
            return false;
        };
        cmdline_bytes
            .split(|b| *b == 0)
            .filter_map(|part| std::str::from_utf8(part).ok())
            .any(|arg| arg.to_ascii_lowercase().contains("copilot"))
    }

    /// Extract session/conversation IDs from headers and body
    fn extract_sessions(&self, request: &RequestInfo) -> Vec<ExtractedSession> {
        let mut sessions = Vec::new();
        let body_json = request
            .body
            .as_ref()
            .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok());

        // Check headers for session identifiers
        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();

            // LangChain session headers
            if key_lower == "x-langchain-run-id" || key_lower == "langchain-run-id" {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::LangChainRun,
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::LangChainRun,
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }
            if key_lower == "x-langchain-trace-id" || key_lower == "langchain-trace-id" {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::LangChainTrace,
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::LangChainTrace,
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }
            if key_lower == "x-langchain-session-id" || key_lower == "langchain-session-id" {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::LangChainRun,
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::LangChainRun,
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }

            // OpenAI headers
            if key_lower == "x-request-id" && request.hostname.contains("openai") {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::OpenAIRequest,
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::OpenAIRequest,
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }
            if key_lower == "openai-organization" {
                // Not a session but useful context
            }

            // Anthropic headers
            if key_lower == "x-request-id" && request.hostname.contains("anthropic") {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::AnthropicRequest,
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::AnthropicRequest,
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }

            // Generic trace/session headers
            if key_lower == "x-trace-id" || key_lower == "trace-id" || key_lower == "traceparent" {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::TraceId,
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::TraceId,
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }
            if key_lower == "x-session-id" || key_lower == "session-id" {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::Custom("Session".to_string()),
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::Custom("Session".to_string()),
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }
            if key_lower == "x-conversation-id" || key_lower == "conversation-id" {
                sessions.push(ExtractedSession {
                    session_id: value.clone(),
                    session_type: SessionType::ClaudeConversation,
                    session_name: self.derive_session_name(
                        value,
                        &SessionType::ClaudeConversation,
                        &request.headers,
                        body_json.as_ref(),
                    ),
                });
            }

            // Stainless SDK headers (used by official SDKs)
            if key_lower == "x-stainless-retry-count" {
                // Indicates SDK retry, not a session
            }
        }

        // Check request body for session information
        if let Some(json) = body_json {
                // Claude Code conversation ID in metadata
                if let Some(metadata) = json.get("metadata") {
                    if let Some(conv_id) = metadata.get("conversation_id").and_then(|v| v.as_str())
                    {
                        sessions.push(ExtractedSession {
                            session_id: conv_id.to_string(),
                            session_type: SessionType::ClaudeConversation,
                            session_name: self.derive_session_name(
                                conv_id,
                                &SessionType::ClaudeConversation,
                                &request.headers,
                                Some(&json),
                            ),
                        });
                    }
                    if let Some(session_id) = metadata.get("session_id").and_then(|v| v.as_str()) {
                        sessions.push(ExtractedSession {
                            session_id: session_id.to_string(),
                            session_type: SessionType::Custom("Session".to_string()),
                            session_name: self.derive_session_name(
                                session_id,
                                &SessionType::Custom("Session".to_string()),
                                &request.headers,
                                Some(&json),
                            ),
                        });
                    }
                    if let Some(run_id) = metadata.get("run_id").and_then(|v| v.as_str()) {
                        sessions.push(ExtractedSession {
                            session_id: run_id.to_string(),
                            session_type: SessionType::LangChainRun,
                            session_name: self.derive_session_name(
                                run_id,
                                &SessionType::LangChainRun,
                                &request.headers,
                                Some(&json),
                            ),
                        });
                    }
                }

                // LangChain includes run_id in some requests
                if let Some(run_id) = json.get("run_id").and_then(|v| v.as_str()) {
                    sessions.push(ExtractedSession {
                        session_id: run_id.to_string(),
                        session_type: SessionType::LangChainRun,
                        session_name: self.derive_session_name(
                            run_id,
                            &SessionType::LangChainRun,
                            &request.headers,
                            Some(&json),
                        ),
                    });
                }

                // Check for thread_id (OpenAI Assistants API)
                if let Some(thread_id) = json.get("thread_id").and_then(|v| v.as_str()) {
                    sessions.push(ExtractedSession {
                        session_id: thread_id.to_string(),
                        session_type: SessionType::Custom("Thread".to_string()),
                        session_name: self.derive_session_name(
                            thread_id,
                            &SessionType::Custom("Thread".to_string()),
                            &request.headers,
                            Some(&json),
                        ),
                    });
                }

                for key in [
                    "sessionId",
                    "agent_session_id",
                    "agentSessionId",
                    "conversationId",
                ] {
                    if let Some(session_id) = json.get(key).and_then(|v| v.as_str()) {
                        sessions.push(ExtractedSession {
                            session_id: session_id.to_string(),
                            session_type: SessionType::Custom("AgentSession".to_string()),
                            session_name: self.derive_session_name(
                                session_id,
                                &SessionType::Custom("AgentSession".to_string()),
                                &request.headers,
                                Some(&json),
                            ),
                        });
                    }
                }

                if let Some(metadata) = json.get("metadata") {
                    for key in [
                        "sessionId",
                        "agent_session_id",
                        "agentSessionId",
                        "conversationId",
                    ] {
                        if let Some(session_id) = metadata.get(key).and_then(|v| v.as_str()) {
                            sessions.push(ExtractedSession {
                                session_id: session_id.to_string(),
                                session_type: SessionType::Custom("AgentSession".to_string()),
                                session_name: self.derive_session_name(
                                    session_id,
                                    &SessionType::Custom("AgentSession".to_string()),
                                    &request.headers,
                                    Some(&json),
                                ),
                            });
                        }
                    }
                }
        }

        if let Some(body) = &request.body {
            let mut idx = 0usize;
            let marker = "RUN-";
            while let Some(pos) = body[idx..].find(marker) {
                let start = idx + pos;
                let tail = &body[start..];
                let end = tail
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                    .unwrap_or(tail.len());
                let run_id = &tail[..end];
                if run_id.len() > 4 {
                    sessions.push(ExtractedSession {
                        session_id: run_id.to_string(),
                        session_type: SessionType::Custom("RunMarker".to_string()),
                        session_name: Some(format!("copilot-run:{}", run_id)),
                    });
                }
                idx = start.saturating_add(end);
                if idx >= body.len() {
                    break;
                }
            }
        }

        if sessions.is_empty() {
            if let Some(process_session) = self.derive_process_context_session(request) {
                sessions.push(process_session);
            }
        }

        sessions
    }

    fn derive_process_context_session(&self, request: &RequestInfo) -> Option<ExtractedSession> {
        let pid = request.pid?;
        let process_name = request
            .process_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let cwd_suffix = std::fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown-cwd".to_string());

        let tty_suffix = std::fs::read_link(format!("/proc/{pid}/fd/0"))
            .ok()
            .map(|p| p.to_string_lossy().to_string())
            .filter(|v| v.contains("/dev/"))
            .unwrap_or_else(|| "no-tty".to_string());

        let derived_session_name = self
            .read_session_name_from_environ(pid)
            .or_else(|| self.read_copilot_workspace_name(pid))
            .or_else(|| self.read_tmux_session_name(&tty_suffix).map(|s| format!("tmux:{s}")))
            .unwrap_or_else(|| format!("{process_name}@{cwd_suffix} ({tty_suffix})"));

        let (session_type, prefix) = if self.looks_like_copilot(request) {
            (
                SessionType::Custom("CopilotProcess".to_string()),
                "copilot-process",
            )
        } else {
            (
                SessionType::Custom("ProcessContext".to_string()),
                "process-session",
            )
        };

        Some(ExtractedSession {
            session_id: format!("{prefix}:{pid}"),
            session_type,
            session_name: Some(derived_session_name),
        })
    }

    fn read_session_name_from_environ(&self, pid: u32) -> Option<String> {
        let data = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
        let candidates = [
            "DHI_SESSION_NAME=",
            "COPILOT_SESSION_NAME=",
            "AGENT_SESSION_NAME=",
            "SESSION_NAME=",
        ];
        for entry in data.split(|b| *b == 0) {
            let Ok(text) = std::str::from_utf8(entry) else {
                continue;
            };
            for key in candidates {
                if let Some(value) = text.strip_prefix(key) {
                    let trimmed = value.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
        None
    }

    fn read_tmux_session_name(&self, tty: &str) -> Option<String> {
        if !tty.starts_with("/dev/pts/") {
            return None;
        }
        let output = Command::new("tmux")
            .args(["display-message", "-p", "-t", tty, "#S"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if name.is_empty() { None } else { Some(name) }
    }

    fn read_copilot_workspace_name(&self, pid: u32) -> Option<String> {
        let home_dir = self
            .read_home_from_environ(pid)
            .or_else(|| std::env::var("HOME").ok())
            .unwrap_or_else(|| "/home/sashank".to_string());
        let base = std::path::PathBuf::from(home_dir).join(".copilot/session-state");
        self.read_copilot_workspace_name_from(&base, pid)
    }

    fn read_home_from_environ(&self, pid: u32) -> Option<String> {
        let data = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
        for entry in data.split(|b| *b == 0) {
            let Ok(text) = std::str::from_utf8(entry) else {
                continue;
            };
            if let Some(home) = text.strip_prefix("HOME=") {
                let trimmed = home.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    fn read_copilot_workspace_name_from(&self, session_state_base: &Path, pid: u32) -> Option<String> {
        let entries = std::fs::read_dir(session_state_base).ok()?;
        let lock_name = format!("inuse.{pid}.lock");
        for entry in entries.filter_map(Result::ok) {
            let dir_path = entry.path();
            if !dir_path.is_dir() {
                continue;
            }
            if !dir_path.join(&lock_name).exists() {
                continue;
            }
            let workspace_path = dir_path.join("workspace.yaml");
            let Ok(content) = std::fs::read_to_string(workspace_path) else {
                continue;
            };
            if let Some(name) = Self::extract_workspace_yaml_name(&content) {
                return Some(name);
            }
        }
        None
    }

    fn extract_workspace_yaml_name(content: &str) -> Option<String> {
        let mut summary: Option<String> = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(v) = trimmed.strip_prefix("name:") {
                let name = v.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
            if let Some(v) = trimmed.strip_prefix("summary:") {
                let s = v.trim();
                if !s.is_empty() {
                    summary = Some(s.to_string());
                }
            }
        }
        summary
    }

    fn derive_session_name(
        &self,
        session_id: &str,
        session_type: &SessionType,
        headers: &HashMap<String, String>,
        body_json: Option<&serde_json::Value>,
    ) -> Option<String> {
        let header_name_keys = [
            "x-session-name",
            "session-name",
            "x-conversation-name",
            "conversation-name",
            "x-thread-name",
            "thread-name",
            "x-run-name",
            "run-name",
        ];

        for (key, value) in headers {
            let key_lower = key.to_ascii_lowercase();
            if header_name_keys.contains(&key_lower.as_str()) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        if let Some(json) = body_json {
            let root_keys = [
                "session_name",
                "conversation_name",
                "thread_name",
                "run_name",
                "name",
            ];
            for key in root_keys {
                if let Some(name) = json.get(key).and_then(|v| v.as_str()) {
                    let trimmed = name.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }

            if let Some(metadata) = json.get("metadata") {
                for key in root_keys {
                    if let Some(name) = metadata.get(key).and_then(|v| v.as_str()) {
                        let trimmed = name.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                }
            }
        }

        let prefix = match session_type {
            SessionType::ClaudeConversation => "conversation",
            SessionType::LangChainRun => "run",
            SessionType::LangChainTrace => "trace",
            SessionType::TraceId => "trace",
            SessionType::OpenAIRequest => "openai-request",
            SessionType::AnthropicRequest => "anthropic-request",
            SessionType::Custom(name) => name,
        };
        Some(format!("{}:{}", prefix, session_id))
    }

    /// Extract model name from request body
    fn extract_model(&self, body: &Option<String>) -> Option<String> {
        if let Some(body) = body {
            // Try to parse as JSON and extract model field
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(model) = json.get("model").and_then(|v| v.as_str()) {
                    return Some(model.to_string());
                }
            }

            // Fallback: regex-like extraction
            if let Some(start) = body.find("\"model\":") {
                let rest = &body[start + 8..];
                if let Some(quote_start) = rest.find('"') {
                    let rest = &rest[quote_start + 1..];
                    if let Some(quote_end) = rest.find('"') {
                        return Some(rest[..quote_end].to_string());
                    }
                }
            }
        }
        None
    }

    /// Hash user agent for fingerprinting
    fn hash_user_agent(&self, ua: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        ua.hash(&mut hasher);
        format!("{:x}", hasher.finish())[..8].to_string()
    }

    /// Record a security event for an agent
    pub fn record_security_event(
        &self,
        fingerprint_id: &str,
        event_type: &str,
        severity: &str,
        details: &str,
    ) {
        if let Ok(mut agents) = self.agents.write() {
            if let Some(agent) = agents.get_mut(fingerprint_id) {
                agent.security_events.push(SecurityEvent {
                    event_type: event_type.to_string(),
                    severity: severity.to_string(),
                    timestamp: SystemTime::now(),
                    details: details.to_string(),
                });

                // Update risk score based on severity
                let severity_score = match severity {
                    "critical" => 30,
                    "high" => 20,
                    "medium" => 10,
                    "low" => 5,
                    _ => 0,
                };
                agent.risk_score = (agent.risk_score + severity_score).min(100);
            }
        }
    }

    /// Update token usage for an agent
    pub fn record_usage(&self, fingerprint_id: &str, tokens: u64, cost: f64) {
        if let Ok(mut agents) = self.agents.write() {
            if let Some(agent) = agents.get_mut(fingerprint_id) {
                agent.total_tokens += tokens;
                agent.estimated_cost += cost;
            }
        }
    }

    pub fn record_tool_calls(&self, fingerprint_id: &str, tool_calls: u64) {
        if tool_calls == 0 {
            return;
        }
        if let Ok(mut agents) = self.agents.write() {
            if let Some(agent) = agents.get_mut(fingerprint_id) {
                agent.total_tool_calls = agent.total_tool_calls.saturating_add(tool_calls);
            }
        }
    }

    pub fn record_session_runtime_usage(
        &self,
        fingerprint_id: &str,
        session_id: &str,
        tokens: u64,
        tool_calls: u64,
    ) {
        if session_id.trim().is_empty() || (tokens == 0 && tool_calls == 0) {
            return;
        }
        if let Ok(mut agents) = self.agents.write() {
            if let Some(agent) = agents.get_mut(fingerprint_id) {
                if let Some(session) = agent.sessions.get_mut(session_id) {
                    session.total_tokens = session.total_tokens.saturating_add(tokens);
                    session.total_tool_calls = session.total_tool_calls.saturating_add(tool_calls);
                }
            }
        }
    }

    pub fn upsert_session(
        &self,
        fingerprint_id: &str,
        session_id: &str,
        session_type: SessionType,
        session_name: Option<String>,
        model: Option<String>,
    ) {
        if session_id.trim().is_empty() {
            return;
        }

        if let Ok(mut agents) = self.agents.write() {
            let Some(agent) = agents.get_mut(fingerprint_id) else {
                return;
            };

            let session = agent
                .sessions
                .entry(session_id.to_string())
                .or_insert_with(|| SessionInfo {
                    session_id: session_id.to_string(),
                    session_type: session_type.clone(),
                    session_name: session_name.clone(),
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    request_count: 0,
                    models: vec![],
                    total_tokens: 0,
                    total_tool_calls: 0,
                });

            session.last_seen = SystemTime::now();
            session.request_count = session.request_count.saturating_add(1);
            if session.session_name.is_none() && session_name.is_some() {
                session.session_name = session_name;
            }
            if let Some(m) = model {
                if !session.models.contains(&m) {
                    session.models.push(m);
                }
            }
        }
    }

    pub fn request_session_ids(&self, request: &RequestInfo) -> Vec<String> {
        let mut ids: Vec<String> = self
            .extract_sessions(request)
            .into_iter()
            .map(|s| s.session_id)
            .filter(|s| !s.trim().is_empty())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Get all sessions across all agents
    pub fn get_all_sessions(&self) -> Vec<(String, SessionInfo)> {
        self.agents
            .read()
            .map(|agents| {
                agents
                    .values()
                    .flat_map(|a| {
                        a.sessions
                            .values()
                            .map(|s| (a.id.clone(), s.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get active sessions in the last N minutes
    pub fn get_active_sessions(&self, minutes: u64) -> Vec<(String, SessionInfo)> {
        let cutoff = SystemTime::now() - Duration::from_secs(minutes * 60);

        self.agents
            .read()
            .map(|agents| {
                agents
                    .values()
                    .flat_map(|a| {
                        a.sessions
                            .values()
                            .filter(|s| s.last_seen > cutoff)
                            .map(|s| (a.id.clone(), s.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all known agents
    pub fn get_all_agents(&self) -> Vec<AgentFingerprint> {
        self.agents
            .read()
            .map(|agents| agents.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get agent by fingerprint ID
    pub fn get_agent(&self, fingerprint_id: &str) -> Option<AgentFingerprint> {
        self.agents
            .read()
            .ok()
            .and_then(|agents| agents.get(fingerprint_id).cloned())
    }

    /// Get agents active in the last N minutes
    pub fn get_active_agents(&self, minutes: u64) -> Vec<AgentFingerprint> {
        let cutoff = SystemTime::now() - Duration::from_secs(minutes * 60);

        self.agents
            .read()
            .map(|agents| {
                agents
                    .values()
                    .filter(|a| a.last_seen > cutoff)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get high-risk agents (risk_score > threshold)
    pub fn get_high_risk_agents(&self, threshold: u32) -> Vec<AgentFingerprint> {
        self.agents
            .read()
            .map(|agents| {
                agents
                    .values()
                    .filter(|a| a.risk_score > threshold)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Generate analysis report
    pub fn generate_report(&self) -> AgentAnalysisReport {
        let agents = self.get_all_agents();
        let active_agents = self.get_active_agents(60);
        let all_sessions = self.get_all_sessions();
        let active_sessions = self.get_active_sessions(60);

        // Count by framework
        let mut framework_counts: HashMap<String, u64> = HashMap::new();
        let mut provider_counts: HashMap<String, u64> = HashMap::new();
        let mut model_counts: HashMap<String, u64> = HashMap::new();
        let mut session_type_counts: HashMap<String, u64> = HashMap::new();

        let mut total_requests = 0u64;
        let mut total_tokens = 0u64;
        let mut total_tool_calls = 0u64;
        let mut total_cost = 0.0f64;
        let mut total_security_events = 0usize;

        for agent in &agents {
            *framework_counts
                .entry(agent.framework.name().to_string())
                .or_insert(0) += 1;

            for provider in &agent.providers {
                *provider_counts
                    .entry(provider.name().to_string())
                    .or_insert(0) += 1;
            }

            for model in &agent.models {
                *model_counts.entry(model.clone()).or_insert(0) += 1;
            }

            // Count session types
            for session in agent.sessions.values() {
                *session_type_counts
                    .entry(session.session_type.name().to_string())
                    .or_insert(0) += 1;
            }

            total_requests += agent.request_count;
            total_tokens += agent.total_tokens;
            total_tool_calls += agent.total_tool_calls;
            total_cost += agent.estimated_cost;
            total_security_events += agent.security_events.len();
        }

        let high_risk_agents: Vec<_> = agents
            .iter()
            .filter(|a| a.risk_score > 50)
            .map(|a| HighRiskAgentSummary {
                id: a.id.clone(),
                framework: a.framework.name().to_string(),
                risk_score: a.risk_score,
                security_events: a.security_events.len(),
            })
            .collect();

        AgentAnalysisReport {
            generated_at: SystemTime::now(),
            total_agents: agents.len(),
            active_agents: active_agents.len(),
            total_sessions: all_sessions.len(),
            active_sessions: active_sessions.len(),
            framework_distribution: framework_counts,
            provider_distribution: provider_counts,
            model_usage: model_counts,
            session_type_distribution: session_type_counts,
            total_requests,
            total_tokens,
            total_tool_calls,
            total_estimated_cost: total_cost,
            total_security_events,
            high_risk_agents,
            agents,
        }
    }
}

impl Default for AgentFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

/// Request information for fingerprinting
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub hostname: String,
    pub path: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub user_agent: Option<String>,
    pub body: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub exe_path: Option<String>,
}

/// Summary of a high-risk agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighRiskAgentSummary {
    pub id: String,
    pub framework: String,
    pub risk_score: u32,
    pub security_events: usize,
}

/// Full agent analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAnalysisReport {
    pub generated_at: SystemTime,
    pub total_agents: usize,
    pub active_agents: usize,
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub framework_distribution: HashMap<String, u64>,
    pub provider_distribution: HashMap<String, u64>,
    pub model_usage: HashMap<String, u64>,
    pub session_type_distribution: HashMap<String, u64>,
    pub total_requests: u64,
    pub total_tokens: u64,
    pub total_tool_calls: u64,
    pub total_estimated_cost: f64,
    pub total_security_events: usize,
    pub high_risk_agents: Vec<HighRiskAgentSummary>,
    pub agents: Vec<AgentFingerprint>,
}

/// Generate a random ID
fn rand_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", nanos)[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_detection() {
        assert_eq!(
            LlmProvider::from_hostname("api.openai.com"),
            LlmProvider::OpenAI
        );
        assert_eq!(
            LlmProvider::from_hostname("api.anthropic.com"),
            LlmProvider::Anthropic
        );
        assert_eq!(
            LlmProvider::from_hostname("my-endpoint.openai.azure.com"),
            LlmProvider::Azure
        );
        assert_eq!(
            LlmProvider::from_hostname("bedrock-runtime.us-east-1.amazonaws.com"),
            LlmProvider::Bedrock
        );
    }

    #[test]
    fn test_framework_detection_from_process() {
        let fingerprinter = AgentFingerprinter::new();

        let request = RequestInfo {
            hostname: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: None,
            body: None,
            process_name: Some("claude".to_string()),
            pid: Some(12345),
            exe_path: None,
        };

        let framework = fingerprinter.detect_framework(&request);
        assert_eq!(framework, AgentFramework::ClaudeCode);
    }

    #[test]
    fn test_framework_detection_from_user_agent() {
        let fingerprinter = AgentFingerprinter::new();

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: Some("openai-python/1.12.0".to_string()),
            body: None,
            process_name: None,
            pid: None,
            exe_path: None,
        };

        let framework = fingerprinter.detect_framework(&request);
        assert_eq!(framework, AgentFramework::OpenAIPython);
    }

    #[test]
    fn test_framework_detection_from_headers() {
        let fingerprinter = AgentFingerprinter::new();

        let mut headers = HashMap::new();
        headers.insert("X-LangChain-Request".to_string(), "true".to_string());

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers,
            user_agent: None,
            body: None,
            process_name: None,
            pid: None,
            exe_path: None,
        };

        let framework = fingerprinter.detect_framework(&request);
        assert_eq!(framework, AgentFramework::LangChain);
    }

    #[test]
    fn test_model_extraction() {
        let fingerprinter = AgentFingerprinter::new();

        let body = r#"{"model": "gpt-4", "messages": []}"#;
        let model = fingerprinter.extract_model(&Some(body.to_string()));
        assert_eq!(model, Some("gpt-4".to_string()));
    }

    #[test]
    fn test_fingerprint_tracking() {
        let fingerprinter = AgentFingerprinter::new();

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: Some("openai-python/1.12.0".to_string()),
            body: Some(r#"{"model": "gpt-4"}"#.to_string()),
            process_name: Some("python".to_string()),
            pid: Some(1234),
            exe_path: None,
        };

        // First request
        let fp1 = fingerprinter.analyze_request(&request);
        assert_eq!(fp1.request_count, 1);
        assert!(fp1.models.contains(&"gpt-4".to_string()));

        // Second request
        let fp2 = fingerprinter.analyze_request(&request);
        assert_eq!(fp2.request_count, 2);
    }

    #[test]
    fn test_security_events() {
        let fingerprinter = AgentFingerprinter::new();

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: None,
            body: None,
            process_name: Some("python".to_string()),
            pid: Some(5678),
            exe_path: None,
        };

        let fp = fingerprinter.analyze_request(&request);

        // Record security event
        fingerprinter.record_security_event(
            &fp.id,
            "secret_detected",
            "critical",
            "OpenAI API key in prompt",
        );

        let updated = fingerprinter.get_agent(&fp.id).unwrap();
        assert_eq!(updated.security_events.len(), 1);
        assert_eq!(updated.risk_score, 30);
    }

    #[test]
    fn test_report_generation() {
        let fingerprinter = AgentFingerprinter::new();

        // Add some agents
        let request1 = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: Some("langchain/0.1.0".to_string()),
            body: Some(r#"{"model": "gpt-4"}"#.to_string()),
            process_name: Some("python".to_string()),
            pid: Some(1111),
            exe_path: None,
        };

        let request2 = RequestInfo {
            hostname: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: None,
            body: Some(r#"{"model": "claude-3-opus"}"#.to_string()),
            process_name: Some("claude".to_string()),
            pid: Some(2222),
            exe_path: None,
        };

        fingerprinter.analyze_request(&request1);
        fingerprinter.analyze_request(&request1);
        fingerprinter.analyze_request(&request2);

        let report = fingerprinter.generate_report();

        assert_eq!(report.total_agents, 2);
        assert!(report.framework_distribution.contains_key("LangChain"));
        assert!(report.framework_distribution.contains_key("Claude Code"));
        assert!(report.provider_distribution.contains_key("OpenAI"));
        assert!(report.provider_distribution.contains_key("Anthropic"));
    }

    #[test]
    fn test_session_extraction() {
        let fingerprinter = AgentFingerprinter::new();

        let mut headers = HashMap::new();
        headers.insert("X-LangChain-Run-Id".to_string(), "run-abc-123".to_string());
        headers.insert(
            "X-LangChain-Trace-Id".to_string(),
            "trace-xyz-789".to_string(),
        );

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers,
            user_agent: Some("langchain/0.1.0".to_string()),
            body: Some(r#"{"model": "gpt-4"}"#.to_string()),
            process_name: Some("python".to_string()),
            pid: Some(3333),
            exe_path: None,
        };

        let fp = fingerprinter.analyze_request(&request);

        assert_eq!(fp.sessions.len(), 2);
        assert!(fp.sessions.contains_key("run-abc-123"));
        assert!(fp.sessions.contains_key("trace-xyz-789"));

        // Verify session types
        let run_session = fp.sessions.get("run-abc-123").unwrap();
        assert_eq!(run_session.session_type, SessionType::LangChainRun);

        let trace_session = fp.sessions.get("trace-xyz-789").unwrap();
        assert_eq!(trace_session.session_type, SessionType::LangChainTrace);
    }

    #[test]
    fn test_session_from_body() {
        let fingerprinter = AgentFingerprinter::new();

        let body = r#"{
            "model": "claude-3-opus",
            "metadata": {
                "conversation_id": "conv-12345",
                "session_id": "sess-67890"
            }
        }"#;

        let request = RequestInfo {
            hostname: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: None,
            body: Some(body.to_string()),
            process_name: Some("claude".to_string()),
            pid: Some(4444),
            exe_path: None,
        };

        let fp = fingerprinter.analyze_request(&request);

        assert!(fp.sessions.contains_key("conv-12345"));
        assert!(fp.sessions.contains_key("sess-67890"));

        let conv_session = fp.sessions.get("conv-12345").unwrap();
        assert_eq!(conv_session.session_type, SessionType::ClaudeConversation);
    }

    #[test]
    fn test_session_name_extracted_from_body() {
        let fingerprinter = AgentFingerprinter::new();
        let body = r#"{
            "model": "gpt-4",
            "metadata": {
                "session_id": "sess-123",
                "session_name": "Weekly Sprint Planning"
            }
        }"#;

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: Some("copilot-cli/1.0".to_string()),
            body: Some(body.to_string()),
            process_name: Some("copilot".to_string()),
            pid: Some(7777),
            exe_path: None,
        };

        let fp = fingerprinter.analyze_request(&request);
        let session = fp.sessions.get("sess-123").unwrap();
        assert_eq!(
            session.session_name.as_deref(),
            Some("Weekly Sprint Planning")
        );
    }

    #[test]
    fn test_detect_copilot_from_mainthread_pid_exe() {
        let fingerprinter = AgentFingerprinter::new();
        let pid = std::process::id();
        let request = RequestInfo {
            hostname: "api.githubcopilot.com".to_string(),
            path: "/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: None,
            body: Some(r#"{"model":"gpt-4o"}"#.to_string()),
            process_name: Some("MainThread".to_string()),
            pid: Some(pid),
            exe_path: std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().to_string()),
        };
        let framework = fingerprinter.detect_framework(&request);
        assert!(matches!(
            framework,
            AgentFramework::CopilotCli | AgentFramework::Unknown(_)
        ));
    }

    #[test]
    fn test_session_request_counting() {
        let fingerprinter = AgentFingerprinter::new();

        let mut headers = HashMap::new();
        headers.insert("X-Session-Id".to_string(), "my-session".to_string());

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: headers.clone(),
            user_agent: None,
            body: Some(r#"{"model": "gpt-4"}"#.to_string()),
            process_name: Some("python".to_string()),
            pid: Some(5555),
            exe_path: None,
        };

        // First request
        fingerprinter.analyze_request(&request);

        // Second request (same session)
        fingerprinter.analyze_request(&request);

        // Third request (same session)
        let fp = fingerprinter.analyze_request(&request);

        let session = fp.sessions.get("my-session").unwrap();
        assert_eq!(session.request_count, 3);
    }

    #[test]
    fn test_run_marker_session_extraction() {
        let fingerprinter = AgentFingerprinter::new();
        let request = RequestInfo {
            hostname: "api.githubcopilot.com".to_string(),
            path: "/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: Some("copilot-cli/1.0".to_string()),
            body: Some("hello RUN-TEST-9001 world".to_string()),
            process_name: Some("MainThread".to_string()),
            pid: Some(8888),
            exe_path: Some("/home/test/.local/bin/copilot".to_string()),
        };

        let fp = fingerprinter.analyze_request(&request);
        let session = fp.sessions.get("RUN-TEST-9001").unwrap();
        assert_eq!(
            session.session_name.as_deref(),
            Some("copilot-run:RUN-TEST-9001")
        );
    }

    #[test]
    fn test_fallback_process_session_when_no_explicit_signals() {
        let fingerprinter = AgentFingerprinter::new();
        let pid = std::process::id();
        let request = RequestInfo {
            hostname: "api.githubcopilot.com".to_string(),
            path: "/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            user_agent: None,
            body: Some("{\"model\":\"gpt-4o\"}".to_string()),
            process_name: Some("MainThread".to_string()),
            pid: Some(pid),
            exe_path: std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().to_string()),
        };

        let fp = fingerprinter.analyze_request(&request);
        let key = format!("process-session:{pid}");
        let fallback = fp
            .sessions
            .get(&key)
            .expect("process-context fallback session should exist");
        assert_eq!(
            fallback.session_type,
            SessionType::Custom("ProcessContext".to_string())
        );
        assert!(fallback.session_name.is_some());
    }

    #[test]
    fn test_explicit_session_prevents_process_fallback() {
        let fingerprinter = AgentFingerprinter::new();
        let mut headers = HashMap::new();
        headers.insert("X-Session-Id".to_string(), "sess-explicit".to_string());

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers,
            user_agent: Some("openai-node/1.0".to_string()),
            body: Some("{\"model\":\"gpt-4\"}".to_string()),
            process_name: Some("node".to_string()),
            pid: Some(std::process::id()),
            exe_path: None,
        };

        let fp = fingerprinter.analyze_request(&request);
        assert!(fp.sessions.contains_key("sess-explicit"));
        let synthetic_key = format!("process-session:{}", std::process::id());
        assert!(!fp.sessions.contains_key(&synthetic_key));
    }

    #[test]
    fn test_extract_workspace_yaml_name_prefers_name() {
        let yaml = "id: abc\nsummary: Clone DHI Repository Locally\nname: dhi-test\n";
        let name = AgentFingerprinter::extract_workspace_yaml_name(yaml);
        assert_eq!(name.as_deref(), Some("dhi-test"));
    }

    #[test]
    fn test_read_copilot_workspace_name_from_lock_match() {
        use std::fs::{create_dir_all, write};
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic here")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("dhi-copilot-meta-{nanos}"));
        let session_dir = root.join("session-x");
        create_dir_all(&session_dir).expect("should create session test dir");

        let pid = 424242;
        write(session_dir.join(format!("inuse.{pid}.lock")), "").expect("should create lock file");
        write(
            session_dir.join("workspace.yaml"),
            "id: session-x\nname: dhi-test2\nsummary: fallback\n",
        )
        .expect("should create workspace.yaml");

        let fp = AgentFingerprinter::new();
        let resolved = fp.read_copilot_workspace_name_from(&root, pid);
        assert_eq!(resolved.as_deref(), Some("dhi-test2"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_record_usage_and_tool_calls_updates_agent_and_session() {
        let fingerprinter = AgentFingerprinter::new();
        let mut headers = HashMap::new();
        headers.insert("X-Session-Id".to_string(), "sess-metrics".to_string());

        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers,
            user_agent: Some("copilot-cli/1.0".to_string()),
            body: Some("{\"model\":\"gpt-4\"}".to_string()),
            process_name: Some("copilot".to_string()),
            pid: Some(424242),
            exe_path: Some("/usr/bin/copilot".to_string()),
        };

        let fp = fingerprinter.analyze_request(&request);
        fingerprinter.record_usage(&fp.id, 21, 0.0);
        fingerprinter.record_tool_calls(&fp.id, 3);
        fingerprinter.record_session_runtime_usage(&fp.id, "sess-metrics", 21, 3);

        let updated = fingerprinter
            .get_agent(&fp.id)
            .expect("agent should exist after update");
        assert_eq!(updated.total_tokens, 21);
        assert_eq!(updated.total_tool_calls, 3);
        let sess = updated
            .sessions
            .get("sess-metrics")
            .expect("session should exist");
        assert_eq!(sess.total_tokens, 21);
        assert_eq!(sess.total_tool_calls, 3);
    }

    #[test]
    fn test_request_session_ids_dedup() {
        let fingerprinter = AgentFingerprinter::new();
        let mut headers = HashMap::new();
        headers.insert("X-Session-Id".to_string(), "dup-session".to_string());
        headers.insert("Session-Id".to_string(), "dup-session".to_string());
        let request = RequestInfo {
            hostname: "api.openai.com".to_string(),
            path: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers,
            user_agent: None,
            body: Some("{\"model\":\"gpt-4\"}".to_string()),
            process_name: Some("python".to_string()),
            pid: Some(12),
            exe_path: None,
        };
        let ids = fingerprinter.request_session_ids(&request);
        assert_eq!(ids, vec!["dup-session".to_string()]);
    }
}

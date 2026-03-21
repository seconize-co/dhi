//! Agent Fingerprinting Module
//!
//! Automatically identifies AI agents, frameworks, and LLM providers
//! from intercepted traffic patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
            || host_lower.contains("aiplatform.googleapis.com") {
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
            AgentFramework::ClaudeCode | AgentFramework::CopilotCli |
            AgentFramework::Cursor | AgentFramework::Windsurf | 
            AgentFramework::Aider => "AI Coding Assistant",
            
            AgentFramework::LangChain | AgentFramework::LlamaIndex |
            AgentFramework::CrewAI | AgentFramework::AutoGen |
            AgentFramework::Haystack => "Agent Framework",
            
            AgentFramework::OpenAIPython | AgentFramework::OpenAINode |
            AgentFramework::AnthropicPython | AgentFramework::AnthropicNode => "SDK",
            
            _ => "Other",
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
    /// First seen timestamp
    pub first_seen: SystemTime,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Total requests
    pub request_count: u64,
    /// Total tokens (estimated)
    pub total_tokens: u64,
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
        
        // Get or create fingerprint
        let mut agents = self.agents.write().unwrap_or_else(|e| e.into_inner());
        
        let fingerprint = agents.entry(fingerprint_id.clone()).or_insert_with(|| {
            AgentFingerprint {
                id: fingerprint_id.clone(),
                framework: framework.clone(),
                providers: vec![],
                process_name: request.process_name.clone(),
                pid: request.pid,
                user_agent: request.user_agent.clone(),
                custom_headers: HashMap::new(),
                models: vec![],
                first_seen: SystemTime::now(),
                last_seen: SystemTime::now(),
                request_count: 0,
                total_tokens: 0,
                estimated_cost: 0.0,
                risk_score: 0,
                security_events: vec![],
            }
        });
        
        // Update fingerprint
        fingerprint.last_seen = SystemTime::now();
        fingerprint.request_count += 1;
        
        if !fingerprint.providers.contains(&provider) {
            fingerprint.providers.push(provider);
        }
        
        if let Some(m) = model {
            if !fingerprint.models.contains(&m) {
                fingerprint.models.push(m);
            }
        }
        
        // Store custom headers
        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();
            if key_lower.starts_with("x-") || key_lower.contains("langchain") 
                || key_lower.contains("openai") || key_lower.contains("anthropic") {
                fingerprint.custom_headers.insert(key.clone(), value.clone());
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
        for (key, _value) in &request.headers {
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
        details: &str
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
    
    /// Get all known agents
    pub fn get_all_agents(&self) -> Vec<AgentFingerprint> {
        self.agents.read()
            .map(|agents| agents.values().cloned().collect())
            .unwrap_or_default()
    }
    
    /// Get agent by fingerprint ID
    pub fn get_agent(&self, fingerprint_id: &str) -> Option<AgentFingerprint> {
        self.agents.read()
            .ok()
            .and_then(|agents| agents.get(fingerprint_id).cloned())
    }
    
    /// Get agents active in the last N minutes
    pub fn get_active_agents(&self, minutes: u64) -> Vec<AgentFingerprint> {
        let cutoff = SystemTime::now() - Duration::from_secs(minutes * 60);
        
        self.agents.read()
            .map(|agents| {
                agents.values()
                    .filter(|a| a.last_seen > cutoff)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get high-risk agents (risk_score > threshold)
    pub fn get_high_risk_agents(&self, threshold: u32) -> Vec<AgentFingerprint> {
        self.agents.read()
            .map(|agents| {
                agents.values()
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
        
        // Count by framework
        let mut framework_counts: HashMap<String, u64> = HashMap::new();
        let mut provider_counts: HashMap<String, u64> = HashMap::new();
        let mut model_counts: HashMap<String, u64> = HashMap::new();
        
        let mut total_requests = 0u64;
        let mut total_tokens = 0u64;
        let mut total_cost = 0.0f64;
        let mut total_security_events = 0usize;
        
        for agent in &agents {
            *framework_counts.entry(agent.framework.name().to_string()).or_insert(0) += 1;
            
            for provider in &agent.providers {
                *provider_counts.entry(provider.name().to_string()).or_insert(0) += 1;
            }
            
            for model in &agent.models {
                *model_counts.entry(model.clone()).or_insert(0) += 1;
            }
            
            total_requests += agent.request_count;
            total_tokens += agent.total_tokens;
            total_cost += agent.estimated_cost;
            total_security_events += agent.security_events.len();
        }
        
        let high_risk_agents: Vec<_> = agents.iter()
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
            framework_distribution: framework_counts,
            provider_distribution: provider_counts,
            model_usage: model_counts,
            total_requests,
            total_tokens,
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
    pub framework_distribution: HashMap<String, u64>,
    pub provider_distribution: HashMap<String, u64>,
    pub model_usage: HashMap<String, u64>,
    pub total_requests: u64,
    pub total_tokens: u64,
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
        assert_eq!(LlmProvider::from_hostname("api.openai.com"), LlmProvider::OpenAI);
        assert_eq!(LlmProvider::from_hostname("api.anthropic.com"), LlmProvider::Anthropic);
        assert_eq!(LlmProvider::from_hostname("my-endpoint.openai.azure.com"), LlmProvider::Azure);
        assert_eq!(LlmProvider::from_hostname("bedrock-runtime.us-east-1.amazonaws.com"), LlmProvider::Bedrock);
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
}

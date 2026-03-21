//! Agentic Runtime Module
//!
//! Provides AI agent-specific monitoring:
//! - LLM API call tracking
//! - Tool invocation monitoring
//! - MCP protocol analysis
//! - Prompt security
//! - Memory protection

mod llm_monitor;
mod mcp_monitor;
mod memory_protection;
mod prompt_security;
mod tool_monitor;

pub use llm_monitor::*;
pub use mcp_monitor::*;
pub use memory_protection::*;
pub use prompt_security::*;
pub use tool_monitor::*;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Agent event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEventType {
    LlmRequest,
    LlmResponse,
    ToolCall,
    ToolResult,
    McpToolInvoke,
    McpResourceAccess,
    MemoryRead,
    MemoryWrite,
    ContextInjection,
    PromptInjectionAttempt,
    JailbreakAttempt,
    SensitiveDataExposure,
    BudgetExceeded,
    AgentSpawn,
    AgentTerminate,
}

/// Agent context - tracks per-agent state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    pub agent_id: String,
    pub framework: String,
    pub created_at: i64,
    pub parent_agent_id: Option<String>,

    // Metrics
    pub llm_calls: u64,
    pub tool_invocations: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,

    // Memory tracking
    pub memory_operations: u64,
    pub context_size_bytes: u64,

    // Risk assessment
    pub risk_score: u32,
    pub suspicious_flags: u32,
    pub blocked: bool,

    // Tool usage
    pub tools_used: HashSet<String>,
    pub denied_tools: HashSet<String>,
}

impl AgentContext {
    pub fn new(agent_id: &str, framework: &str, parent_id: Option<&str>) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            framework: framework.to_string(),
            created_at: chrono::Utc::now().timestamp(),
            parent_agent_id: parent_id.map(|s| s.to_string()),
            llm_calls: 0,
            tool_invocations: 0,
            total_tokens: 0,
            total_cost_usd: 0.0,
            memory_operations: 0,
            context_size_bytes: 0,
            risk_score: 0,
            suspicious_flags: 0,
            blocked: false,
            tools_used: HashSet::new(),
            denied_tools: HashSet::new(),
        }
    }
}

/// LLM call tracking result
#[derive(Debug, Clone, Serialize)]
pub struct LlmCallResult {
    pub call_id: String,
    pub total_tokens: u64,
    pub cost_usd: f64,
    pub risk_score: u32,
    pub alerts: Vec<String>,
}

/// Tool call tracking result
#[derive(Debug, Clone, Serialize)]
pub struct ToolCallResult {
    pub invocation_id: String,
    pub allowed: bool,
    pub risk_level: String,
    pub risk_score: u32,
    pub flags: Vec<String>,
}

/// Memory verification result
#[derive(Debug, Clone, Serialize)]
pub struct MemoryVerifyResult {
    pub verified: bool,
    pub tampered: bool,
    pub key: String,
}

/// Context verification result
#[derive(Debug, Clone, Serialize)]
pub struct ContextVerifyResult {
    pub injection_detected: bool,
    pub suspicious_messages: Vec<usize>,
    pub risk_score: u32,
}

/// Overall runtime statistics
#[derive(Debug, Clone, Serialize)]
pub struct OverallStats {
    pub total_agents: usize,
    pub total_llm_calls: u64,
    pub total_tool_invocations: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub total_events: u64,
    pub high_risk_agents: Vec<String>,
}

/// Main agentic runtime
pub struct AgenticRuntime {
    agents: Arc<RwLock<HashMap<String, AgentContext>>>,
    llm_monitor: Arc<LlmMonitor>,
    tool_monitor: Arc<ToolMonitor>,
    mcp_monitor: Arc<McpMonitor>,
    prompt_security: Arc<PromptSecurityAnalyzer>,
    memory_protection: Arc<RwLock<MemoryProtection>>,
    events: Arc<RwLock<Vec<AgentEvent>>>,
    total_events: Arc<RwLock<u64>>,
}

/// Agent event
#[derive(Debug, Clone, Serialize)]
pub struct AgentEvent {
    pub timestamp: i64,
    pub event_type: AgentEventType,
    pub agent_id: String,
    pub data: serde_json::Value,
}

impl AgenticRuntime {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            llm_monitor: Arc::new(LlmMonitor::new()),
            tool_monitor: Arc::new(ToolMonitor::new()),
            mcp_monitor: Arc::new(McpMonitor::new()),
            prompt_security: Arc::new(PromptSecurityAnalyzer::new()),
            memory_protection: Arc::new(RwLock::new(MemoryProtection::new())),
            events: Arc::new(RwLock::new(Vec::new())),
            total_events: Arc::new(RwLock::new(0)),
        }
    }

    /// Register a new agent for monitoring
    pub async fn register_agent(
        &self,
        agent_id: &str,
        framework: &str,
        parent_id: Option<&str>,
    ) {
        let context = AgentContext::new(agent_id, framework, parent_id);
        self.agents.write().await.insert(agent_id.to_string(), context);

        self.emit_event(AgentEventType::AgentSpawn, agent_id, serde_json::json!({
            "framework": framework,
            "parent_id": parent_id,
        })).await;

        info!("Agent registered: {} (framework: {})", agent_id, framework);
    }

    /// Track an LLM API call
    pub async fn track_llm_call(
        &self,
        agent_id: &str,
        provider: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        prompt: Option<String>,
        has_tools: bool,
        tool_names: Vec<String>,
    ) -> LlmCallResult {
        let call_id = format!("{}-{}", agent_id, chrono::Utc::now().timestamp_millis());
        let total_tokens = input_tokens + output_tokens;
        let cost_usd = self.llm_monitor.estimate_cost(model, input_tokens, output_tokens);

        let mut risk_score = 0u32;
        let mut alerts = Vec::new();

        // Analyze prompt security if provided
        if let Some(ref prompt_text) = prompt {
            let security = self.prompt_security.analyze(prompt_text);

            if security.injection_detected {
                risk_score += 40;
                alerts.push("prompt_injection_detected".to_string());
                self.emit_event(AgentEventType::PromptInjectionAttempt, agent_id, serde_json::json!({
                    "call_id": call_id,
                    "findings": security.findings,
                })).await;
                warn!("Prompt injection detected for agent {}", agent_id);
            }

            if security.jailbreak_detected {
                risk_score += 30;
                alerts.push("jailbreak_attempt_detected".to_string());
                self.emit_event(AgentEventType::JailbreakAttempt, agent_id, serde_json::json!({
                    "call_id": call_id,
                    "findings": security.findings,
                })).await;
                warn!("Jailbreak attempt detected for agent {}", agent_id);
            }

            if security.sensitive_data_detected {
                risk_score += 25;
                alerts.push("sensitive_data_in_prompt".to_string());
                self.emit_event(AgentEventType::SensitiveDataExposure, agent_id, serde_json::json!({
                    "call_id": call_id,
                })).await;
            }
        }

        // Update agent context
        if let Some(ctx) = self.agents.write().await.get_mut(agent_id) {
            ctx.llm_calls += 1;
            ctx.total_tokens += total_tokens;
            ctx.total_cost_usd += cost_usd;
            ctx.risk_score = ctx.risk_score.max(risk_score);
        }

        self.emit_event(AgentEventType::LlmRequest, agent_id, serde_json::json!({
            "call_id": call_id,
            "provider": provider,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost_usd,
            "has_tools": has_tools,
            "tool_names": tool_names,
        })).await;

        info!(
            "LLM Call: {} -> {}/{} ({}+{} tokens, ${:.4})",
            agent_id, provider, model, input_tokens, output_tokens, cost_usd
        );

        LlmCallResult {
            call_id,
            total_tokens,
            cost_usd,
            risk_score,
            alerts,
        }
    }

    /// Track a tool invocation
    pub async fn track_tool_call(
        &self,
        agent_id: &str,
        tool_name: &str,
        tool_type: &str,
        parameters: serde_json::Value,
    ) -> ToolCallResult {
        let invocation_id = format!("{}-tool-{}", agent_id, chrono::Utc::now().timestamp_millis());

        // Analyze risk
        let risk = self.tool_monitor.analyze_tool_call(tool_name, &parameters);

        let mut result = ToolCallResult {
            invocation_id: invocation_id.clone(),
            allowed: true,
            risk_level: risk.risk_level.clone(),
            risk_score: risk.risk_score,
            flags: risk.flags.clone(),
        };

        // Check denylist
        if self.tool_monitor.is_denied(tool_name) {
            result.allowed = false;
            result.flags.push(format!("tool_denied:{}", tool_name));

            if let Some(ctx) = self.agents.write().await.get_mut(agent_id) {
                ctx.denied_tools.insert(tool_name.to_string());
            }
        }

        // Update agent context
        if let Some(ctx) = self.agents.write().await.get_mut(agent_id) {
            ctx.tool_invocations += 1;
            ctx.tools_used.insert(tool_name.to_string());
            ctx.risk_score = ctx.risk_score.max(risk.risk_score);
        }

        self.emit_event(AgentEventType::ToolCall, agent_id, serde_json::json!({
            "invocation_id": invocation_id,
            "tool_name": tool_name,
            "tool_type": tool_type,
            "parameters": parameters,
            "risk": risk,
            "allowed": result.allowed,
        })).await;

        let log_level = if risk.risk_level == "high" || risk.risk_level == "critical" {
            tracing::Level::WARN
        } else {
            tracing::Level::INFO
        };

        match log_level {
            tracing::Level::WARN => warn!(
                "Tool Call: {} -> {} (type: {}, risk: {})",
                agent_id, tool_name, tool_type, risk.risk_level
            ),
            _ => info!(
                "Tool Call: {} -> {} (type: {}, risk: {})",
                agent_id, tool_name, tool_type, risk.risk_level
            ),
        }

        result
    }

    /// Protect agent memory
    pub async fn protect_memory(&self, agent_id: &str, key: &str, value: &str) {
        let mut protection = self.memory_protection.write().await;
        protection.protect(agent_id, key, value);

        self.emit_event(AgentEventType::MemoryWrite, agent_id, serde_json::json!({
            "key": key,
            "protected": true,
        })).await;
    }

    /// Verify memory integrity
    pub async fn verify_memory(&self, agent_id: &str, key: &str, value: &str) -> MemoryVerifyResult {
        let protection = self.memory_protection.read().await;
        let result = protection.verify(agent_id, key, value);

        if result.tampered {
            self.emit_event(AgentEventType::ContextInjection, agent_id, serde_json::json!({
                "key": key,
                "tampered": true,
            })).await;
            warn!("Memory tampering detected: {}/{}", agent_id, key);
        }

        result
    }

    /// Verify context integrity
    pub async fn verify_context(&self, agent_id: &str, messages: &[serde_json::Value]) -> ContextVerifyResult {
        let protection = self.memory_protection.read().await;
        let result = protection.detect_context_injection(messages);

        if result.injection_detected {
            self.emit_event(AgentEventType::ContextInjection, agent_id, serde_json::json!({
                "suspicious_messages": result.suspicious_messages,
            })).await;
            warn!("Context injection detected for agent {}", agent_id);
        }

        result
    }

    /// Get agent statistics
    pub async fn get_agent_stats(&self, agent_id: &str) -> Option<serde_json::Value> {
        let agents = self.agents.read().await;
        agents.get(agent_id).map(|ctx| {
            let uptime = chrono::Utc::now().timestamp() - ctx.created_at;
            serde_json::json!({
                "agent_id": ctx.agent_id,
                "framework": ctx.framework,
                "uptime_seconds": uptime,
                "llm_calls": ctx.llm_calls,
                "tool_invocations": ctx.tool_invocations,
                "total_tokens": ctx.total_tokens,
                "total_cost_usd": ctx.total_cost_usd,
                "risk_score": ctx.risk_score,
                "tools_used": ctx.tools_used.iter().collect::<Vec<_>>(),
                "denied_tools": ctx.denied_tools.iter().collect::<Vec<_>>(),
                "suspicious_flags": ctx.suspicious_flags,
                "blocked": ctx.blocked,
            })
        })
    }

    /// Get overall statistics
    pub async fn get_overall_stats(&self) -> OverallStats {
        let agents = self.agents.read().await;
        let total_events = *self.total_events.read().await;

        let mut total_llm_calls = 0;
        let mut total_tool_invocations = 0;
        let mut total_tokens = 0;
        let mut total_cost_usd = 0.0;
        let mut high_risk_agents = Vec::new();

        for (id, ctx) in agents.iter() {
            total_llm_calls += ctx.llm_calls;
            total_tool_invocations += ctx.tool_invocations;
            total_tokens += ctx.total_tokens;
            total_cost_usd += ctx.total_cost_usd;

            if ctx.risk_score >= 50 {
                high_risk_agents.push(id.clone());
            }
        }

        OverallStats {
            total_agents: agents.len(),
            total_llm_calls,
            total_tool_invocations,
            total_tokens,
            total_cost_usd,
            total_events,
            high_risk_agents,
        }
    }

    /// Emit an event
    async fn emit_event(&self, event_type: AgentEventType, agent_id: &str, data: serde_json::Value) {
        let event = AgentEvent {
            timestamp: chrono::Utc::now().timestamp(),
            event_type,
            agent_id: agent_id.to_string(),
            data,
        };

        self.events.write().await.push(event);
        *self.total_events.write().await += 1;
    }
}

impl Default for AgenticRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the agentic monitor background task
pub async fn start_agentic_monitor() -> Result<()> {
    info!("Agentic monitor started");
    // In production, this would set up HTTP interception, etc.
    Ok(())
}

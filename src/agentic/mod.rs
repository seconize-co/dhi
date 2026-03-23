//! Agentic Runtime Module
//!
//! Provides AI agent-specific monitoring:
//! - LLM API call tracking
//! - Tool invocation monitoring
//! - MCP protocol analysis
//! - Prompt security
//! - Memory protection
//! - Secrets detection
//! - PII detection
//! - Efficiency analysis
//! - Budget control
//! - Alerting
//! - Metrics
//! - Data protection
//! - Agent fingerprinting
#![allow(clippy::too_many_arguments)]

mod alerting;
mod budget;
mod data_protection;
mod efficiency;
mod fingerprint;
mod llm_monitor;
mod mcp_monitor;
mod memory_protection;
mod metrics;
mod pii_detector;
mod prompt_security;
mod secrets_detector;
mod tool_monitor;

#[cfg(test)]
mod tests;

pub use alerting::*;
pub use budget::*;
pub use data_protection::*;
pub use efficiency::*;
pub use fingerprint::*;
pub use llm_monitor::*;
pub use mcp_monitor::*;
pub use memory_protection::*;
pub use metrics::*;
pub use pii_detector::*;
pub use prompt_security::*;
pub use secrets_detector::*;
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

/// Optional trace context to enrich runtime alerts for operator investigation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertTraceContext {
    pub correlation_id: Option<String>,
    pub session_id: Option<String>,
    pub session_name: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub destination: Option<String>,
    pub path: Option<String>,
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

/// Maximum number of events to store (circular buffer)
const MAX_EVENTS: usize = 10_000;

/// Main agentic runtime
pub struct AgenticRuntime {
    agents: Arc<RwLock<HashMap<String, AgentContext>>>,
    llm_monitor: Arc<LlmMonitor>,
    budget_controller: Arc<BudgetController>,
    tool_monitor: Arc<ToolMonitor>,
    _mcp_monitor: Arc<McpMonitor>,
    prompt_security: Arc<PromptSecurityAnalyzer>,
    alerter: Arc<Alerter>,
    fingerprinter: Arc<AgentFingerprinter>,
    memory_protection: Arc<RwLock<MemoryProtection>>,
    events: Arc<RwLock<CircularEventBuffer>>,
    total_events: Arc<RwLock<u64>>,
}

/// Circular buffer for events to prevent unbounded memory growth
struct CircularEventBuffer {
    events: Vec<AgentEvent>,
    head: usize,
    len: usize,
    capacity: usize,
}

impl CircularEventBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            head: 0,
            len: 0,
            capacity,
        }
    }

    fn push(&mut self, event: AgentEvent) {
        if self.events.len() < self.capacity {
            // Still filling up
            self.events.push(event);
            self.len += 1;
        } else {
            // Circular overwrite
            self.events[self.head] = event;
            self.head = (self.head + 1) % self.capacity;
        }
    }
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
        Self::new_with_alert_config(AlertConfig::default())
    }

    pub fn new_with_alert_config(alert_config: AlertConfig) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            llm_monitor: Arc::new(LlmMonitor::new()),
            budget_controller: Arc::new(BudgetController::new()),
            tool_monitor: Arc::new(ToolMonitor::new()),
            _mcp_monitor: Arc::new(McpMonitor::new()),
            prompt_security: Arc::new(PromptSecurityAnalyzer::new()),
            alerter: Arc::new(Alerter::new(alert_config)),
            fingerprinter: Arc::new(AgentFingerprinter::new()),
            memory_protection: Arc::new(RwLock::new(MemoryProtection::new())),
            events: Arc::new(RwLock::new(CircularEventBuffer::new(MAX_EVENTS))),
            total_events: Arc::new(RwLock::new(0)),
        }
    }

    pub fn fingerprinter(&self) -> Arc<AgentFingerprinter> {
        Arc::clone(&self.fingerprinter)
    }

    pub fn configure_max_budget_usd(&self, max_budget_usd: f64) {
        self.budget_controller.set_global_limit(BudgetLimit {
            daily_usd: max_budget_usd,
            monthly_usd: max_budget_usd * 30.0,
            per_call_usd: None,
        });
    }

    /// Register a new agent for monitoring
    pub async fn register_agent(&self, agent_id: &str, framework: &str, parent_id: Option<&str>) {
        let context = AgentContext::new(agent_id, framework, parent_id);
        self.agents
            .write()
            .await
            .insert(agent_id.to_string(), context);

        self.emit_event(
            AgentEventType::AgentSpawn,
            agent_id,
            serde_json::json!({
                "framework": framework,
                "parent_id": parent_id,
            }),
        )
        .await;

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
        self.track_llm_call_with_context(
            agent_id,
            provider,
            model,
            input_tokens,
            output_tokens,
            prompt,
            has_tools,
            tool_names,
            None,
        )
        .await
    }

    pub async fn track_llm_call_with_context(
        &self,
        agent_id: &str,
        provider: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        prompt: Option<String>,
        has_tools: bool,
        tool_names: Vec<String>,
        trace: Option<AlertTraceContext>,
    ) -> LlmCallResult {
        let call_id = format!("{}-{}", agent_id, chrono::Utc::now().timestamp_millis());
        let total_tokens = input_tokens + output_tokens;
        let cost_usd = self
            .llm_monitor
            .estimate_cost(model, input_tokens, output_tokens);
        let budget_check = self.budget_controller.check_budget(agent_id, cost_usd);

        let mut risk_score = 0u32;
        let mut alerts = Vec::new();

        if budget_check.status.is_warning {
            alerts.push("budget_warning".to_string());
            let alert_result = if let Some(ref ctx) = trace {
                let mut alert = Alert::new(
                    AlertSeverity::Warning,
                    "Budget Warning Threshold Reached",
                    &format!(
                        "Agent {} has reached budget warning: ${:.2}/${:.2} ({:.1}%)",
                        agent_id,
                        budget_check.status.daily_spent,
                        budget_check.status.daily_limit,
                        budget_check.status.daily_percent_used
                    ),
                )
                .with_agent(agent_id)
                .with_use_case_id("sze.dhi.budget.uc01.detect")
                .with_event_type("budget_warning")
                .with_metadata("spent", serde_json::json!(budget_check.status.daily_spent))
                .with_metadata("limit", serde_json::json!(budget_check.status.daily_limit))
                .with_metadata(
                    "percent_used",
                    serde_json::json!(budget_check.status.daily_percent_used),
                );
                apply_alert_trace_context(&mut alert, ctx);
                self.alerter.send(&alert).await
            } else {
                self.alerter
                    .alert_budget_warning(
                        agent_id,
                        budget_check.status.daily_spent,
                        budget_check.status.daily_limit,
                        budget_check.status.daily_percent_used,
                    )
                    .await
            };
            if let Err(err) = alert_result {
                warn!("Failed to dispatch budget warning alert for {agent_id}: {err}");
            }
        }
        if !budget_check.allowed {
            risk_score += 50;
            alerts.push("budget_exceeded".to_string());
            let alert_result = if let Some(ref ctx) = trace {
                let mut alert = Alert::new(
                    AlertSeverity::Error,
                    "Budget Limit Exceeded",
                    &format!(
                        "Agent {} has exceeded budget: ${:.2} spent, ${:.2} limit",
                        agent_id, budget_check.status.daily_spent, budget_check.status.daily_limit
                    ),
                )
                .with_agent(agent_id)
                .with_use_case_id("sze.dhi.budget.uc02.block")
                .with_event_type("budget_exceeded")
                .with_metadata("spent", serde_json::json!(budget_check.status.daily_spent))
                .with_metadata("limit", serde_json::json!(budget_check.status.daily_limit));
                apply_alert_trace_context(&mut alert, ctx);
                self.alerter.send(&alert).await
            } else {
                self.alerter
                    .alert_budget_exceeded(
                        agent_id,
                        budget_check.status.daily_spent,
                        budget_check.status.daily_limit,
                    )
                    .await
            };
            if let Err(err) = alert_result {
                warn!("Failed to dispatch budget exceeded alert for {agent_id}: {err}");
            }
            self.emit_event(
                AgentEventType::BudgetExceeded,
                agent_id,
                serde_json::json!({
                    "call_id": call_id,
                    "cost_usd": cost_usd,
                    "reason": budget_check.reason.clone(),
                }),
            )
            .await;
            warn!("Budget exceeded for agent {}", agent_id);
        }

        // Analyze prompt security if provided
        if let Some(ref prompt_text) = prompt {
            let security = self.prompt_security.analyze(prompt_text);

            if security.injection_detected {
                risk_score += 40;
                alerts.push("prompt_injection_detected".to_string());
                if let Some(finding) = security.findings.first() {
                    let alert_result = if let Some(ref ctx) = trace {
                        let mut alert = Alert::new(
                            AlertSeverity::Critical,
                            "Prompt Injection Attempt Detected",
                            &format!(
                                "Prompt injection attempt detected for agent {}: {}",
                                agent_id, finding.pattern
                            ),
                        )
                        .with_agent(agent_id)
                        .with_use_case_id("sze.dhi.prompt.uc01.detect")
                        .with_event_type("prompt_injection")
                        .with_metadata("pattern", serde_json::json!(finding.pattern));
                        apply_alert_trace_context(&mut alert, ctx);
                        self.alerter.send(&alert).await
                    } else {
                        self.alerter
                            .alert_prompt_injection(agent_id, &finding.pattern)
                            .await
                    };
                    if let Err(err) = alert_result {
                        warn!("Failed to dispatch prompt injection alert for {agent_id}: {err}");
                    }
                }
                self.emit_event(
                    AgentEventType::PromptInjectionAttempt,
                    agent_id,
                    serde_json::json!({
                        "call_id": call_id,
                        "findings": security.findings,
                    }),
                )
                .await;
                warn!("Prompt injection detected for agent {}", agent_id);
            }

            if security.jailbreak_detected {
                risk_score += 30;
                alerts.push("jailbreak_attempt_detected".to_string());
                self.emit_event(
                    AgentEventType::JailbreakAttempt,
                    agent_id,
                    serde_json::json!({
                        "call_id": call_id,
                        "findings": security.findings,
                    }),
                )
                .await;
                warn!("Jailbreak attempt detected for agent {}", agent_id);
            }

            if security.sensitive_data_detected {
                risk_score += 25;
                alerts.push("sensitive_data_in_prompt".to_string());
                self.emit_event(
                    AgentEventType::SensitiveDataExposure,
                    agent_id,
                    serde_json::json!({
                        "call_id": call_id,
                    }),
                )
                .await;
            }
        }

        // Update agent context
        if let Some(ctx) = self.agents.write().await.get_mut(agent_id) {
            ctx.llm_calls += 1;
            ctx.total_tokens += total_tokens;
            ctx.total_cost_usd += cost_usd;
            ctx.risk_score = ctx.risk_score.max(risk_score);
        }
        self.budget_controller.record_spend(agent_id, cost_usd);

        self.emit_event(
            AgentEventType::LlmRequest,
            agent_id,
            serde_json::json!({
                "call_id": call_id,
                "provider": provider,
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost_usd,
                "budget_allowed": budget_check.allowed,
                "budget_warning": budget_check.status.is_warning,
                "has_tools": has_tools,
                "tool_names": tool_names,
            }),
        )
        .await;

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
        self.track_tool_call_with_context(agent_id, tool_name, tool_type, parameters, None)
            .await
    }

    pub async fn track_tool_call_with_context(
        &self,
        agent_id: &str,
        tool_name: &str,
        tool_type: &str,
        parameters: serde_json::Value,
        trace: Option<AlertTraceContext>,
    ) -> ToolCallResult {
        let invocation_id = format!(
            "{}-tool-{}",
            agent_id,
            chrono::Utc::now().timestamp_millis()
        );

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

        self.emit_event(
            AgentEventType::ToolCall,
            agent_id,
            serde_json::json!({
                "invocation_id": invocation_id,
                "tool_name": tool_name,
                "tool_type": tool_type,
                "parameters": parameters,
                "risk": risk,
                "allowed": result.allowed,
            }),
        )
        .await;

        let log_level = if risk.risk_level == "high" || risk.risk_level == "critical" {
            tracing::Level::WARN
        } else {
            tracing::Level::INFO
        };

        if risk.risk_score >= 50 {
            let action = if result.allowed { "ALLOWED" } else { "BLOCKED" };
            let alert_result = if let Some(ref ctx) = trace {
                let mut alert = Alert::new(
                    if risk.risk_score >= 80 {
                        AlertSeverity::Error
                    } else {
                        AlertSeverity::Warning
                    },
                    "High-Risk Tool Invocation",
                    &format!(
                        "Agent {} invoked tool '{}' with {} risk (score: {}).",
                        agent_id, tool_name, risk.risk_level, risk.risk_score
                    ),
                )
                .with_agent(agent_id)
                .with_use_case_id(if action == "BLOCKED" {
                    "sze.dhi.tools.uc02.block"
                } else {
                    "sze.dhi.tools.uc01.detect"
                })
                .with_event_type("tool_risk")
                .with_metadata("tool_name", serde_json::json!(tool_name))
                .with_metadata("risk_level", serde_json::json!(risk.risk_level))
                .with_metadata("risk_score", serde_json::json!(risk.risk_score))
                .with_action(action);
                apply_alert_trace_context(&mut alert, ctx);
                self.alerter.send(&alert).await
            } else {
                self.alerter
                    .alert_tool_risk(
                        agent_id,
                        tool_name,
                        &risk.risk_level,
                        risk.risk_score,
                        action,
                    )
                    .await
            };
            if let Err(err) = alert_result {
                warn!("Failed to dispatch tool risk alert for {agent_id}: {err}");
            }
        }

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

        self.emit_event(
            AgentEventType::MemoryWrite,
            agent_id,
            serde_json::json!({
                "key": key,
                "protected": true,
            }),
        )
        .await;
    }

    /// Verify memory integrity
    pub async fn verify_memory(
        &self,
        agent_id: &str,
        key: &str,
        value: &str,
    ) -> MemoryVerifyResult {
        let protection = self.memory_protection.read().await;
        let result = protection.verify(agent_id, key, value);

        if result.tampered {
            self.emit_event(
                AgentEventType::ContextInjection,
                agent_id,
                serde_json::json!({
                    "key": key,
                    "tampered": true,
                }),
            )
            .await;
            warn!("Memory tampering detected: {}/{}", agent_id, key);
        }

        result
    }

    /// Verify context integrity
    pub async fn verify_context(
        &self,
        agent_id: &str,
        messages: &[serde_json::Value],
    ) -> ContextVerifyResult {
        let protection = self.memory_protection.read().await;
        let result = protection.detect_context_injection(messages);

        if result.injection_detected {
            self.emit_event(
                AgentEventType::ContextInjection,
                agent_id,
                serde_json::json!({
                    "suspicious_messages": result.suspicious_messages,
                }),
            )
            .await;
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
    async fn emit_event(
        &self,
        event_type: AgentEventType,
        agent_id: &str,
        data: serde_json::Value,
    ) {
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

fn apply_alert_trace_context(alert: &mut Alert, trace: &AlertTraceContext) {
    if let Some(ref correlation_id) = trace.correlation_id {
        *alert = alert.clone().with_correlation_id(correlation_id);
    }
    if let Some(ref session_id) = trace.session_id {
        *alert = alert
            .clone()
            .with_session(session_id, trace.session_name.as_deref());
    }
    if trace.process_name.is_some() || trace.pid.is_some() {
        *alert = alert
            .clone()
            .with_process(trace.process_name.as_deref(), trace.pid);
    }
    if trace.destination.is_some() || trace.path.is_some() {
        *alert = alert
            .clone()
            .with_destination(trace.destination.as_deref(), trace.path.as_deref());
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

//! Metrics Module
//!
//! Prometheus-compatible metrics for monitoring.

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use std::sync::Arc;

/// Dhi metrics
pub struct DhiMetrics {
    pub registry: Registry,

    // Event counters
    pub events_total: IntCounterVec,
    pub alerts_total: IntCounterVec,
    pub blocks_total: IntCounterVec,

    // LLM metrics
    pub llm_calls_total: IntCounterVec,
    pub llm_tokens_total: IntCounterVec,
    pub llm_cost_total: CounterVec,
    pub llm_latency: HistogramVec,

    // Tool metrics
    pub tool_calls_total: IntCounterVec,
    pub tool_calls_blocked: IntCounterVec,
    pub tool_risk_score: GaugeVec,

    // Security metrics
    pub secrets_detected: IntCounterVec,
    pub pii_detected: IntCounterVec,
    pub injections_detected: IntCounterVec,

    // Budget metrics
    pub budget_spent: GaugeVec,
    pub budget_remaining: GaugeVec,
    pub budget_exceeded: IntCounterVec,

    // Efficiency metrics
    pub duplicate_prompts: IntCounterVec,
    pub tool_loops: IntCounterVec,

    // Agent metrics
    pub active_agents: IntGauge,
    pub high_risk_agents: IntGauge,

    // System metrics
    pub uptime_seconds: IntGauge,
    pub events_per_second: Gauge,
}

impl DhiMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        // Event counters
        let events_total = IntCounterVec::new(
            Opts::new("dhi_events_total", "Total events processed"),
            &["event_type"],
        )
        .unwrap();

        let alerts_total = IntCounterVec::new(
            Opts::new("dhi_alerts_total", "Total alerts generated"),
            &["severity", "event_type"],
        )
        .unwrap();

        let blocks_total = IntCounterVec::new(
            Opts::new("dhi_blocks_total", "Total blocked operations"),
            &["reason"],
        )
        .unwrap();

        // LLM metrics
        let llm_calls_total = IntCounterVec::new(
            Opts::new("dhi_llm_calls_total", "Total LLM API calls"),
            &["provider", "model", "agent_id"],
        )
        .unwrap();

        let llm_tokens_total = IntCounterVec::new(
            Opts::new("dhi_llm_tokens_total", "Total tokens used"),
            &["provider", "direction"], // direction: input/output
        )
        .unwrap();

        let llm_cost_total = CounterVec::new(
            Opts::new("dhi_llm_cost_usd_total", "Total LLM cost in USD"),
            &["provider", "agent_id"],
        )
        .unwrap();

        let llm_latency = HistogramVec::new(
            HistogramOpts::new("dhi_llm_latency_seconds", "LLM call latency")
                .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]),
            &["provider"],
        )
        .unwrap();

        // Tool metrics
        let tool_calls_total = IntCounterVec::new(
            Opts::new("dhi_tool_calls_total", "Total tool invocations"),
            &["tool_name", "tool_type", "agent_id"],
        )
        .unwrap();

        let tool_calls_blocked = IntCounterVec::new(
            Opts::new("dhi_tool_calls_blocked_total", "Blocked tool calls"),
            &["tool_name", "reason"],
        )
        .unwrap();

        let tool_risk_score = GaugeVec::new(
            Opts::new("dhi_tool_risk_score", "Current tool risk score"),
            &["agent_id"],
        )
        .unwrap();

        // Security metrics
        let secrets_detected = IntCounterVec::new(
            Opts::new("dhi_secrets_detected_total", "Secrets detected"),
            &["secret_type", "severity"],
        )
        .unwrap();

        let pii_detected = IntCounterVec::new(
            Opts::new("dhi_pii_detected_total", "PII instances detected"),
            &["pii_type"],
        )
        .unwrap();

        let injections_detected = IntCounterVec::new(
            Opts::new("dhi_injections_detected_total", "Injection attempts"),
            &["injection_type"],
        )
        .unwrap();

        // Budget metrics
        let budget_spent = GaugeVec::new(
            Opts::new("dhi_budget_spent_usd", "Current budget spent"),
            &["agent_id", "period"], // period: daily/monthly
        )
        .unwrap();

        let budget_remaining = GaugeVec::new(
            Opts::new("dhi_budget_remaining_usd", "Budget remaining"),
            &["agent_id", "period"],
        )
        .unwrap();

        let budget_exceeded = IntCounterVec::new(
            Opts::new("dhi_budget_exceeded_total", "Budget limit exceeded"),
            &["agent_id"],
        )
        .unwrap();

        // Efficiency metrics
        let duplicate_prompts = IntCounterVec::new(
            Opts::new("dhi_duplicate_prompts_total", "Duplicate prompts detected"),
            &["agent_id"],
        )
        .unwrap();

        let tool_loops = IntCounterVec::new(
            Opts::new("dhi_tool_loops_total", "Tool loops detected"),
            &["agent_id", "tool_name"],
        )
        .unwrap();

        // Agent metrics
        let active_agents = IntGauge::new(
            "dhi_active_agents",
            "Number of active agents",
        )
        .unwrap();

        let high_risk_agents = IntGauge::new(
            "dhi_high_risk_agents",
            "Number of high-risk agents",
        )
        .unwrap();

        // System metrics
        let uptime_seconds = IntGauge::new(
            "dhi_uptime_seconds",
            "Dhi runtime uptime in seconds",
        )
        .unwrap();

        let events_per_second = Gauge::new(
            "dhi_events_per_second",
            "Events processed per second",
        )
        .unwrap();

        // Register all metrics
        registry.register(Box::new(events_total.clone())).unwrap();
        registry.register(Box::new(alerts_total.clone())).unwrap();
        registry.register(Box::new(blocks_total.clone())).unwrap();
        registry.register(Box::new(llm_calls_total.clone())).unwrap();
        registry.register(Box::new(llm_tokens_total.clone())).unwrap();
        registry.register(Box::new(llm_cost_total.clone())).unwrap();
        registry.register(Box::new(llm_latency.clone())).unwrap();
        registry.register(Box::new(tool_calls_total.clone())).unwrap();
        registry.register(Box::new(tool_calls_blocked.clone())).unwrap();
        registry.register(Box::new(tool_risk_score.clone())).unwrap();
        registry.register(Box::new(secrets_detected.clone())).unwrap();
        registry.register(Box::new(pii_detected.clone())).unwrap();
        registry.register(Box::new(injections_detected.clone())).unwrap();
        registry.register(Box::new(budget_spent.clone())).unwrap();
        registry.register(Box::new(budget_remaining.clone())).unwrap();
        registry.register(Box::new(budget_exceeded.clone())).unwrap();
        registry.register(Box::new(duplicate_prompts.clone())).unwrap();
        registry.register(Box::new(tool_loops.clone())).unwrap();
        registry.register(Box::new(active_agents.clone())).unwrap();
        registry.register(Box::new(high_risk_agents.clone())).unwrap();
        registry.register(Box::new(uptime_seconds.clone())).unwrap();
        registry.register(Box::new(events_per_second.clone())).unwrap();

        Self {
            registry,
            events_total,
            alerts_total,
            blocks_total,
            llm_calls_total,
            llm_tokens_total,
            llm_cost_total,
            llm_latency,
            tool_calls_total,
            tool_calls_blocked,
            tool_risk_score,
            secrets_detected,
            pii_detected,
            injections_detected,
            budget_spent,
            budget_remaining,
            budget_exceeded,
            duplicate_prompts,
            tool_loops,
            active_agents,
            high_risk_agents,
            uptime_seconds,
            events_per_second,
        }
    }

    /// Record an LLM call
    pub fn record_llm_call(
        &self,
        provider: &str,
        model: &str,
        agent_id: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: f64,
        latency_secs: f64,
    ) {
        self.llm_calls_total
            .with_label_values(&[provider, model, agent_id])
            .inc();
        self.llm_tokens_total
            .with_label_values(&[provider, "input"])
            .inc_by(input_tokens);
        self.llm_tokens_total
            .with_label_values(&[provider, "output"])
            .inc_by(output_tokens);
        self.llm_cost_total
            .with_label_values(&[provider, agent_id])
            .inc_by(cost_usd);
        self.llm_latency
            .with_label_values(&[provider])
            .observe(latency_secs);
    }

    /// Record a tool call
    pub fn record_tool_call(
        &self,
        tool_name: &str,
        tool_type: &str,
        agent_id: &str,
        blocked: bool,
        block_reason: Option<&str>,
    ) {
        self.tool_calls_total
            .with_label_values(&[tool_name, tool_type, agent_id])
            .inc();

        if blocked {
            self.tool_calls_blocked
                .with_label_values(&[tool_name, block_reason.unwrap_or("unknown")])
                .inc();
        }
    }

    /// Record secret detection
    pub fn record_secret(&self, secret_type: &str, severity: &str) {
        self.secrets_detected
            .with_label_values(&[secret_type, severity])
            .inc();
    }

    /// Record PII detection
    pub fn record_pii(&self, pii_type: &str, count: u64) {
        self.pii_detected
            .with_label_values(&[pii_type])
            .inc_by(count);
    }

    /// Record injection attempt
    pub fn record_injection(&self, injection_type: &str) {
        self.injections_detected
            .with_label_values(&[injection_type])
            .inc();
    }

    /// Update budget metrics
    pub fn update_budget(&self, agent_id: &str, daily_spent: f64, daily_remaining: f64) {
        self.budget_spent
            .with_label_values(&[agent_id, "daily"])
            .set(daily_spent);
        self.budget_remaining
            .with_label_values(&[agent_id, "daily"])
            .set(daily_remaining);
    }

    /// Record budget exceeded
    pub fn record_budget_exceeded(&self, agent_id: &str) {
        self.budget_exceeded
            .with_label_values(&[agent_id])
            .inc();
    }

    /// Record duplicate prompt
    pub fn record_duplicate_prompt(&self, agent_id: &str) {
        self.duplicate_prompts
            .with_label_values(&[agent_id])
            .inc();
    }

    /// Record tool loop
    pub fn record_tool_loop(&self, agent_id: &str, tool_name: &str) {
        self.tool_loops
            .with_label_values(&[agent_id, tool_name])
            .inc();
    }

    /// Update agent counts
    pub fn update_agent_counts(&self, active: i64, high_risk: i64) {
        self.active_agents.set(active);
        self.high_risk_agents.set(high_risk);
    }

    /// Update uptime
    pub fn update_uptime(&self, seconds: i64) {
        self.uptime_seconds.set(seconds);
    }

    /// Get metrics in Prometheus format
    pub fn gather(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for DhiMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = DhiMetrics::new();
        
        // Record some metrics
        metrics.record_llm_call("openai", "gpt-4", "agent-1", 100, 50, 0.05, 1.5);
        metrics.record_tool_call("web_search", "mcp", "agent-1", false, None);
        metrics.record_secret("openai_key", "critical");
        metrics.record_pii("email", 3);

        // Gather and check output
        let output = metrics.gather();
        assert!(output.contains("dhi_llm_calls_total"));
        assert!(output.contains("dhi_secrets_detected_total"));
    }
}

//! Efficiency Analyzer
//!
//! Detects inefficiencies in agent behavior:
//! - Duplicate prompts
//! - Repeated tool calls
//! - Token waste
//! - Cost anomalies

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Prompt hash for duplicate detection
type PromptHash = String;

/// Efficiency analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficiencyReport {
    pub total_cost_usd: f64,
    pub potential_savings_usd: f64,
    pub savings_percentage: f64,
    pub issues: Vec<EfficiencyIssue>,
}

/// Individual efficiency issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficiencyIssue {
    pub issue_type: String,
    pub description: String,
    pub occurrences: u32,
    pub agent_id: String,
    pub potential_savings_usd: f64,
    pub recommendation: String,
}

/// Tool call pattern for loop detection
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ToolCallPattern {
    pub tool_name: String,
    pub params_hash: String,
}

/// Efficiency analyzer
pub struct EfficiencyAnalyzer {
    /// Prompt hashes for duplicate detection
    prompt_hashes: RwLock<HashMap<PromptHash, PromptOccurrence>>,
    
    /// Tool call patterns for loop detection
    tool_patterns: RwLock<HashMap<String, Vec<ToolCallRecord>>>,
    
    /// Token usage by agent
    token_usage: RwLock<HashMap<String, TokenUsage>>,
    
    /// Configuration
    config: EfficiencyConfig,
}

#[derive(Debug, Clone)]
struct PromptOccurrence {
    count: u32,
    agent_ids: Vec<String>,
    estimated_cost: f64,
    first_seen: i64,
    last_seen: i64,
}

#[derive(Debug, Clone)]
struct ToolCallRecord {
    tool_name: String,
    params_hash: String,
    timestamp: i64,
    success: bool,
}

#[derive(Debug, Clone, Default)]
struct TokenUsage {
    input_tokens: u64,
    output_tokens: u64,
    context_tokens_used: u64,
    context_tokens_available: u64,
}

/// Efficiency configuration
#[derive(Debug, Clone)]
pub struct EfficiencyConfig {
    pub duplicate_prompt_threshold: u32,
    pub tool_loop_threshold: u32,
    pub tool_loop_window_secs: i64,
    pub context_efficiency_threshold: f64,
    pub cost_anomaly_threshold: f64,
}

impl Default for EfficiencyConfig {
    fn default() -> Self {
        Self {
            duplicate_prompt_threshold: 3,
            tool_loop_threshold: 5,
            tool_loop_window_secs: 60,
            context_efficiency_threshold: 0.3,
            cost_anomaly_threshold: 2.0,
        }
    }
}

impl EfficiencyAnalyzer {
    pub fn new() -> Self {
        Self::with_config(EfficiencyConfig::default())
    }

    pub fn with_config(config: EfficiencyConfig) -> Self {
        Self {
            prompt_hashes: RwLock::new(HashMap::new()),
            tool_patterns: RwLock::new(HashMap::new()),
            token_usage: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Record a prompt for duplicate detection
    pub fn record_prompt(
        &self,
        agent_id: &str,
        prompt_hash: &str,
        estimated_cost: f64,
    ) -> Option<EfficiencyIssue> {
        let mut hashes = match self.prompt_hashes.write() {
            Ok(h) => h,
            Err(_) => return None, // Lock poisoned, skip tracking
        };
        let now = chrono::Utc::now().timestamp();

        let occurrence = hashes
            .entry(prompt_hash.to_string())
            .or_insert_with(|| PromptOccurrence {
                count: 0,
                agent_ids: Vec::new(),
                estimated_cost: 0.0,
                first_seen: now,
                last_seen: now,
            });

        occurrence.count += 1;
        occurrence.estimated_cost += estimated_cost;
        occurrence.last_seen = now;
        
        if !occurrence.agent_ids.contains(&agent_id.to_string()) {
            occurrence.agent_ids.push(agent_id.to_string());
        }

        // Check threshold
        if occurrence.count >= self.config.duplicate_prompt_threshold {
            Some(EfficiencyIssue {
                issue_type: "duplicate_prompt".to_string(),
                description: format!(
                    "Same prompt sent {} times",
                    occurrence.count
                ),
                occurrences: occurrence.count,
                agent_id: agent_id.to_string(),
                potential_savings_usd: occurrence.estimated_cost * 0.8, // 80% could be cached
                recommendation: "Implement prompt caching or check for existing results".to_string(),
            })
        } else {
            None
        }
    }

    /// Record a tool call for loop detection
    pub fn record_tool_call(
        &self,
        agent_id: &str,
        tool_name: &str,
        params_hash: &str,
        success: bool,
    ) -> Option<EfficiencyIssue> {
        let mut patterns = match self.tool_patterns.write() {
            Ok(p) => p,
            Err(_) => return None, // Lock poisoned, skip tracking
        };
        let now = chrono::Utc::now().timestamp();

        let records = patterns
            .entry(agent_id.to_string())
            .or_insert_with(Vec::new);

        // Remove old records outside window
        records.retain(|r| now - r.timestamp < self.config.tool_loop_window_secs);

        // Add new record
        records.push(ToolCallRecord {
            tool_name: tool_name.to_string(),
            params_hash: params_hash.to_string(),
            timestamp: now,
            success,
        });

        // Count identical calls
        let identical_count = records
            .iter()
            .filter(|r| r.tool_name == tool_name && r.params_hash == params_hash)
            .count() as u32;

        // Check for loop
        if identical_count >= self.config.tool_loop_threshold {
            Some(EfficiencyIssue {
                issue_type: "tool_loop".to_string(),
                description: format!(
                    "Tool '{}' called {} times with same parameters in {} seconds",
                    tool_name, identical_count, self.config.tool_loop_window_secs
                ),
                occurrences: identical_count,
                agent_id: agent_id.to_string(),
                potential_savings_usd: 0.0, // Hard to estimate
                recommendation: "Add result caching or loop detection logic".to_string(),
            })
        } else {
            None
        }
    }

    /// Record token usage for efficiency analysis
    pub fn record_token_usage(
        &self,
        agent_id: &str,
        input_tokens: u64,
        output_tokens: u64,
        context_used: u64,
        context_available: u64,
    ) -> Option<EfficiencyIssue> {
        let mut usage = match self.token_usage.write() {
            Ok(u) => u,
            Err(_) => return None, // Lock poisoned, skip tracking
        };
        
        let agent_usage = usage
            .entry(agent_id.to_string())
            .or_insert_with(TokenUsage::default);

        agent_usage.input_tokens += input_tokens;
        agent_usage.output_tokens += output_tokens;
        agent_usage.context_tokens_used += context_used;
        agent_usage.context_tokens_available += context_available;

        // Check context efficiency
        if context_available > 0 {
            let efficiency = context_used as f64 / context_available as f64;
            if efficiency < self.config.context_efficiency_threshold {
                return Some(EfficiencyIssue {
                    issue_type: "context_waste".to_string(),
                    description: format!(
                        "Only {:.1}% of context window used",
                        efficiency * 100.0
                    ),
                    occurrences: 1,
                    agent_id: agent_id.to_string(),
                    potential_savings_usd: 0.0,
                    recommendation: "Consider using a smaller model or context pruning".to_string(),
                });
            }
        }

        None
    }

    /// Generate efficiency report
    pub fn generate_report(&self, _agents: &[String]) -> EfficiencyReport {
        let mut issues = Vec::new();
        let mut total_savings = 0.0;

        // Check for duplicate prompts
        let hashes = match self.prompt_hashes.read() {
            Ok(h) => h,
            Err(_) => return EfficiencyReport {
                total_cost_usd: 0.0,
                potential_savings_usd: 0.0,
                savings_percentage: 0.0,
                issues: vec![],
            },
        };
        for (_, occurrence) in hashes.iter() {
            if occurrence.count >= self.config.duplicate_prompt_threshold {
                let savings = occurrence.estimated_cost * 0.8;
                total_savings += savings;
                issues.push(EfficiencyIssue {
                    issue_type: "duplicate_prompt".to_string(),
                    description: format!("Prompt repeated {} times", occurrence.count),
                    occurrences: occurrence.count,
                    agent_id: occurrence.agent_ids.first().cloned().unwrap_or_default(),
                    potential_savings_usd: savings,
                    recommendation: "Cache repeated prompts".to_string(),
                });
            }
        }

        // Calculate totals (simplified)
        let total_cost = total_savings * 2.5; // Rough estimate

        EfficiencyReport {
            total_cost_usd: total_cost,
            potential_savings_usd: total_savings,
            savings_percentage: if total_cost > 0.0 {
                (total_savings / total_cost) * 100.0
            } else {
                0.0
            },
            issues,
        }
    }

    /// Clear old data
    pub fn cleanup(&self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();

        // Clean prompt hashes
        if let Ok(mut hashes) = self.prompt_hashes.write() {
            hashes.retain(|_, v| now - v.last_seen < max_age_secs);
        }

        // Clean tool patterns
        if let Ok(mut patterns) = self.tool_patterns.write() {
            for records in patterns.values_mut() {
                records.retain(|r| now - r.timestamp < max_age_secs);
            }
            patterns.retain(|_, v| !v.is_empty());
        }
    }
}

impl Default for EfficiencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_prompt_detection() {
        let analyzer = EfficiencyAnalyzer::with_config(EfficiencyConfig {
            duplicate_prompt_threshold: 3,
            ..Default::default()
        });

        // First two calls - no issue
        assert!(analyzer.record_prompt("agent-1", "hash123", 0.01).is_none());
        assert!(analyzer.record_prompt("agent-1", "hash123", 0.01).is_none());

        // Third call - triggers issue
        let issue = analyzer.record_prompt("agent-1", "hash123", 0.01);
        assert!(issue.is_some());
        assert_eq!(issue.unwrap().issue_type, "duplicate_prompt");
    }

    #[test]
    fn test_tool_loop_detection() {
        let analyzer = EfficiencyAnalyzer::with_config(EfficiencyConfig {
            tool_loop_threshold: 3,
            tool_loop_window_secs: 60,
            ..Default::default()
        });

        // First two calls - no issue
        assert!(analyzer.record_tool_call("agent-1", "search", "params123", true).is_none());
        assert!(analyzer.record_tool_call("agent-1", "search", "params123", true).is_none());

        // Third call - triggers loop detection
        let issue = analyzer.record_tool_call("agent-1", "search", "params123", true);
        assert!(issue.is_some());
        assert_eq!(issue.unwrap().issue_type, "tool_loop");
    }
}

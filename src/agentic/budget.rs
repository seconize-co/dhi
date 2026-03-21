//! Budget Controller
//!
//! Enforces spending limits on LLM API calls.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{info, warn};
use chrono::Datelike;

/// Budget limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetLimit {
    pub daily_usd: f64,
    pub monthly_usd: f64,
    pub per_call_usd: Option<f64>,
}

impl Default for BudgetLimit {
    fn default() -> Self {
        Self {
            daily_usd: 100.0,
            monthly_usd: 2000.0,
            per_call_usd: Some(1.0),
        }
    }
}

/// Budget status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetStatus {
    pub daily_spent: f64,
    pub daily_limit: f64,
    pub daily_remaining: f64,
    pub daily_percent_used: f64,
    pub monthly_spent: f64,
    pub monthly_limit: f64,
    pub monthly_remaining: f64,
    pub monthly_percent_used: f64,
    pub is_exceeded: bool,
    pub is_warning: bool,
}

/// Budget check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCheckResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub status: BudgetStatus,
}

/// Agent spending record
#[derive(Debug, Clone, Default)]
struct AgentSpending {
    daily_total: f64,
    monthly_total: f64,
    last_daily_reset: i64,
    last_monthly_reset: i64,
    call_count: u64,
}

impl AgentSpending {
    fn with_current_periods() -> Self {
        let now = chrono::Utc::now();
        let today = now
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .map(|t| t.and_utc().timestamp())
            .unwrap_or(0);
        let this_month = now
            .date_naive()
            .with_day(1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|t| t.and_utc().timestamp())
            .unwrap_or(0);

        Self {
            last_daily_reset: today,
            last_monthly_reset: this_month,
            ..Default::default()
        }
    }
}

/// Budget controller
pub struct BudgetController {
    /// Global limits
    global_limit: RwLock<BudgetLimit>,
    
    /// Per-agent limits
    agent_limits: RwLock<HashMap<String, BudgetLimit>>,
    
    /// Spending tracking
    spending: RwLock<HashMap<String, AgentSpending>>,
    
    /// Global spending
    global_spending: RwLock<AgentSpending>,
    
    /// Warning threshold (percentage)
    warning_threshold: f64,
    
    /// Action on limit exceeded
    action_on_exceeded: BudgetAction,
}

/// Action to take when budget exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BudgetAction {
    /// Block the request
    #[default]
    Block,
    /// Allow but alert
    Alert,
    /// Throttle (slow down)
    Throttle,
}

impl BudgetController {
    pub fn new() -> Self {
        Self {
            global_limit: RwLock::new(BudgetLimit::default()),
            agent_limits: RwLock::new(HashMap::new()),
            spending: RwLock::new(HashMap::new()),
            global_spending: RwLock::new(AgentSpending::default()),
            warning_threshold: 0.8, // 80%
            action_on_exceeded: BudgetAction::Block,
        }
    }

    /// Set global budget limit
    pub fn set_global_limit(&self, limit: BudgetLimit) {
        if let Ok(mut global) = self.global_limit.write() {
            info!("Global budget set: ${}/day, ${}/month", limit.daily_usd, limit.monthly_usd);
            *global = limit;
        }
    }

    /// Set per-agent budget limit
    pub fn set_agent_limit(&self, agent_id: &str, limit: BudgetLimit) {
        if let Ok(mut limits) = self.agent_limits.write() {
            info!("Agent {} budget set: ${}/day, ${}/month", 
                  agent_id, limit.daily_usd, limit.monthly_usd);
            limits.insert(agent_id.to_string(), limit);
        }
    }

    /// Set action on budget exceeded
    pub fn set_action(&mut self, action: BudgetAction) {
        self.action_on_exceeded = action;
    }

    /// Check if a spend is allowed
    pub fn check_budget(&self, agent_id: &str, amount_usd: f64) -> BudgetCheckResult {
        self.reset_if_needed(agent_id);

        // Get locks - if poisoned, return a safe default (deny)
        let global_limit = match self.global_limit.read() {
            Ok(g) => g,
            Err(_) => return BudgetCheckResult {
                allowed: false,
                reason: Some("Internal error: lock poisoned".to_string()),
                status: BudgetStatus::default(),
            },
        };
        
        let agent_limits = match self.agent_limits.read() {
            Ok(a) => a,
            Err(_) => return BudgetCheckResult {
                allowed: false,
                reason: Some("Internal error: lock poisoned".to_string()),
                status: BudgetStatus::default(),
            },
        };
        
        let spending = match self.spending.read() {
            Ok(s) => s,
            Err(_) => return BudgetCheckResult {
                allowed: false,
                reason: Some("Internal error: lock poisoned".to_string()),
                status: BudgetStatus::default(),
            },
        };
        
        let global_spending = match self.global_spending.read() {
            Ok(g) => g,
            Err(_) => return BudgetCheckResult {
                allowed: false,
                reason: Some("Internal error: lock poisoned".to_string()),
                status: BudgetStatus::default(),
            },
        };

        // Get effective limit (agent-specific or global)
        let limit = agent_limits.get(agent_id).unwrap_or(&global_limit);

        // Get current spending
        let agent_spend = spending.get(agent_id).cloned().unwrap_or_default();

        // Check per-call limit
        if let Some(per_call) = limit.per_call_usd {
            if amount_usd > per_call {
                return BudgetCheckResult {
                    allowed: self.action_on_exceeded != BudgetAction::Block,
                    reason: Some(format!(
                        "Single call ${:.4} exceeds per-call limit ${:.2}",
                        amount_usd, per_call
                    )),
                    status: self.build_status(&agent_spend, limit),
                };
            }
        }

        // Check daily limit
        if agent_spend.daily_total + amount_usd > limit.daily_usd {
            return BudgetCheckResult {
                allowed: self.action_on_exceeded != BudgetAction::Block,
                reason: Some(format!(
                    "Daily budget exceeded: ${:.2} + ${:.4} > ${:.2}",
                    agent_spend.daily_total, amount_usd, limit.daily_usd
                )),
                status: self.build_status(&agent_spend, limit),
            };
        }

        // Check monthly limit
        if agent_spend.monthly_total + amount_usd > limit.monthly_usd {
            return BudgetCheckResult {
                allowed: self.action_on_exceeded != BudgetAction::Block,
                reason: Some(format!(
                    "Monthly budget exceeded: ${:.2} + ${:.4} > ${:.2}",
                    agent_spend.monthly_total, amount_usd, limit.monthly_usd
                )),
                status: self.build_status(&agent_spend, limit),
            };
        }

        // Check global limits
        if global_spending.daily_total + amount_usd > global_limit.daily_usd {
            return BudgetCheckResult {
                allowed: self.action_on_exceeded != BudgetAction::Block,
                reason: Some("Global daily budget exceeded".to_string()),
                status: self.build_status(&agent_spend, limit),
            };
        }

        BudgetCheckResult {
            allowed: true,
            reason: None,
            status: self.build_status(&agent_spend, limit),
        }
    }

    /// Record a spend
    pub fn record_spend(&self, agent_id: &str, amount_usd: f64) {
        self.reset_if_needed(agent_id);

        // Update agent spending
        if let Ok(mut spending) = self.spending.write() {
            let agent_spend = spending
                .entry(agent_id.to_string())
                .or_insert_with(AgentSpending::with_current_periods);
            agent_spend.daily_total += amount_usd;
            agent_spend.monthly_total += amount_usd;
            agent_spend.call_count += 1;

            // Check for warnings
            if let Ok(limit) = self.global_limit.read() {
                if limit.daily_usd > 0.0 && agent_spend.daily_total / limit.daily_usd >= self.warning_threshold {
                    warn!(
                        "Agent {} approaching daily budget: ${:.2} / ${:.2} ({:.0}%)",
                        agent_id,
                        agent_spend.daily_total,
                        limit.daily_usd,
                        (agent_spend.daily_total / limit.daily_usd) * 100.0
                    );
                }
            }
        }

        // Update global spending
        if let Ok(mut global) = self.global_spending.write() {
            global.daily_total += amount_usd;
            global.monthly_total += amount_usd;
            global.call_count += 1;
        }
    }

    /// Get spending status for an agent
    pub fn get_status(&self, agent_id: &str) -> BudgetStatus {
        let global_limit = match self.global_limit.read() {
            Ok(g) => g,
            Err(_) => return BudgetStatus::default(),
        };
        let agent_limits = match self.agent_limits.read() {
            Ok(a) => a,
            Err(_) => return BudgetStatus::default(),
        };
        let spending = match self.spending.read() {
            Ok(s) => s,
            Err(_) => return BudgetStatus::default(),
        };

        let limit = agent_limits.get(agent_id).unwrap_or(&global_limit);
        let agent_spend = spending.get(agent_id).cloned().unwrap_or_default();

        self.build_status(&agent_spend, limit)
    }

    /// Get global spending status
    pub fn get_global_status(&self) -> BudgetStatus {
        let limit = match self.global_limit.read() {
            Ok(l) => l,
            Err(_) => return BudgetStatus::default(),
        };
        let global = match self.global_spending.read() {
            Ok(g) => g,
            Err(_) => return BudgetStatus::default(),
        };
        self.build_status(&global, &limit)
    }

    /// Build status object
    fn build_status(&self, spending: &AgentSpending, limit: &BudgetLimit) -> BudgetStatus {
        let daily_percent = if limit.daily_usd > 0.0 {
            (spending.daily_total / limit.daily_usd) * 100.0
        } else {
            0.0
        };

        let monthly_percent = if limit.monthly_usd > 0.0 {
            (spending.monthly_total / limit.monthly_usd) * 100.0
        } else {
            0.0
        };

        BudgetStatus {
            daily_spent: spending.daily_total,
            daily_limit: limit.daily_usd,
            daily_remaining: (limit.daily_usd - spending.daily_total).max(0.0),
            daily_percent_used: daily_percent,
            monthly_spent: spending.monthly_total,
            monthly_limit: limit.monthly_usd,
            monthly_remaining: (limit.monthly_usd - spending.monthly_total).max(0.0),
            monthly_percent_used: monthly_percent,
            is_exceeded: daily_percent >= 100.0 || monthly_percent >= 100.0,
            is_warning: daily_percent >= self.warning_threshold * 100.0 
                || monthly_percent >= self.warning_threshold * 100.0,
        }
    }

    /// Reset counters if day/month changed
    fn reset_if_needed(&self, agent_id: &str) {
        let now = chrono::Utc::now();
        let today = now.date_naive()
            .and_hms_opt(0, 0, 0)
            .map(|t| t.and_utc().timestamp())
            .unwrap_or(0);
        let this_month = now.date_naive()
            .with_day(1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|t| t.and_utc().timestamp())
            .unwrap_or(0);

        if let Ok(mut spending) = self.spending.write() {
            if let Some(agent_spend) = spending.get_mut(agent_id) {
                // Reset daily
                if agent_spend.last_daily_reset < today {
                    agent_spend.daily_total = 0.0;
                    agent_spend.last_daily_reset = today;
                }
                // Reset monthly
                if agent_spend.last_monthly_reset < this_month {
                    agent_spend.monthly_total = 0.0;
                    agent_spend.last_monthly_reset = this_month;
                }
            }
        }

        // Reset global
        if let Ok(mut global) = self.global_spending.write() {
            if global.last_daily_reset < today {
                global.daily_total = 0.0;
                global.last_daily_reset = today;
            }
            if global.last_monthly_reset < this_month {
                global.monthly_total = 0.0;
                global.last_monthly_reset = this_month;
            }
        }
    }
}

impl Default for BudgetController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_check() {
        let controller = BudgetController::new();
        controller.set_global_limit(BudgetLimit {
            daily_usd: 10.0,
            monthly_usd: 100.0,
            per_call_usd: Some(5.0),
        });

        // Should be allowed
        let result = controller.check_budget("agent-1", 1.0);
        assert!(result.allowed);

        // Per-call exceeded
        let result = controller.check_budget("agent-1", 10.0);
        assert!(!result.allowed);
        assert!(result.reason.unwrap().contains("per-call"));
    }

    #[test]
    fn test_spend_tracking() {
        let controller = BudgetController::new();
        controller.set_global_limit(BudgetLimit {
            daily_usd: 10.0,
            monthly_usd: 100.0,
            per_call_usd: None,
        });

        // Record some spending
        controller.record_spend("agent-1", 3.0);
        controller.record_spend("agent-1", 4.0);

        let status = controller.get_status("agent-1");
        assert!((status.daily_spent - 7.0).abs() < 0.001);
        assert!((status.daily_percent_used - 70.0).abs() < 0.1);

        // Should still be allowed
        let result = controller.check_budget("agent-1", 2.0);
        assert!(result.allowed);

        // This would exceed
        let result = controller.check_budget("agent-1", 5.0);
        assert!(!result.allowed);
    }
}

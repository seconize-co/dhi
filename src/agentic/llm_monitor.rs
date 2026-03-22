//! LLM API Monitor
//!
//! Tracks calls to LLM providers with cost estimation.

use std::collections::HashMap;

/// LLM call tracking
#[derive(Debug, Clone)]
pub struct LlmCall {
    pub call_id: String,
    pub timestamp: i64,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub latency_ms: u64,
    pub status: String,
}

/// Model pricing (USD per 1K tokens)
#[derive(Debug, Clone)]
pub struct ModelPricing {
    pub input: f64,
    pub output: f64,
}

/// LLM Monitor
pub struct LlmMonitor {
    pricing: HashMap<String, ModelPricing>,
    pub total_cost: f64,
    pub total_tokens: u64,
    pub budget_limit: Option<f64>,
}

impl LlmMonitor {
    pub fn new() -> Self {
        let mut pricing = HashMap::new();

        // OpenAI pricing
        pricing.insert(
            "gpt-4".to_string(),
            ModelPricing {
                input: 0.03,
                output: 0.06,
            },
        );
        pricing.insert(
            "gpt-4-turbo".to_string(),
            ModelPricing {
                input: 0.01,
                output: 0.03,
            },
        );
        pricing.insert(
            "gpt-4o".to_string(),
            ModelPricing {
                input: 0.005,
                output: 0.015,
            },
        );
        pricing.insert(
            "gpt-4o-mini".to_string(),
            ModelPricing {
                input: 0.00015,
                output: 0.0006,
            },
        );
        pricing.insert(
            "gpt-3.5-turbo".to_string(),
            ModelPricing {
                input: 0.0005,
                output: 0.0015,
            },
        );
        pricing.insert(
            "o1".to_string(),
            ModelPricing {
                input: 0.015,
                output: 0.06,
            },
        );
        pricing.insert(
            "o1-mini".to_string(),
            ModelPricing {
                input: 0.003,
                output: 0.012,
            },
        );

        // Anthropic pricing
        pricing.insert(
            "claude-3-opus".to_string(),
            ModelPricing {
                input: 0.015,
                output: 0.075,
            },
        );
        pricing.insert(
            "claude-3-sonnet".to_string(),
            ModelPricing {
                input: 0.003,
                output: 0.015,
            },
        );
        pricing.insert(
            "claude-3-haiku".to_string(),
            ModelPricing {
                input: 0.00025,
                output: 0.00125,
            },
        );
        pricing.insert(
            "claude-sonnet-4".to_string(),
            ModelPricing {
                input: 0.003,
                output: 0.015,
            },
        );
        pricing.insert(
            "claude-opus-4".to_string(),
            ModelPricing {
                input: 0.015,
                output: 0.075,
            },
        );

        // Google pricing
        pricing.insert(
            "gemini-pro".to_string(),
            ModelPricing {
                input: 0.00025,
                output: 0.0005,
            },
        );
        pricing.insert(
            "gemini-1.5-pro".to_string(),
            ModelPricing {
                input: 0.0025,
                output: 0.0075,
            },
        );
        pricing.insert(
            "gemini-1.5-flash".to_string(),
            ModelPricing {
                input: 0.000075,
                output: 0.0003,
            },
        );

        // Mistral pricing
        pricing.insert(
            "mistral-large".to_string(),
            ModelPricing {
                input: 0.004,
                output: 0.012,
            },
        );
        pricing.insert(
            "mistral-small".to_string(),
            ModelPricing {
                input: 0.001,
                output: 0.003,
            },
        );

        Self {
            pricing,
            total_cost: 0.0,
            total_tokens: 0,
            budget_limit: None,
        }
    }

    /// Estimate cost for an LLM call
    pub fn estimate_cost(&self, model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
        // Find matching pricing
        let pricing = self.find_pricing(model);

        let cost = (input_tokens as f64 / 1000.0 * pricing.input)
            + (output_tokens as f64 / 1000.0 * pricing.output);

        (cost * 10000.0).round() / 10000.0 // Round to 4 decimal places
    }

    /// Find pricing for a model (fuzzy match)
    fn find_pricing(&self, model: &str) -> ModelPricing {
        let model_lower = model.to_lowercase();

        for (key, pricing) in &self.pricing {
            if model_lower.contains(key) {
                return pricing.clone();
            }
        }

        // Default pricing
        ModelPricing {
            input: 0.001,
            output: 0.002,
        }
    }

    /// Check if budget is exceeded
    pub fn is_budget_exceeded(&self) -> bool {
        if let Some(limit) = self.budget_limit {
            self.total_cost > limit
        } else {
            false
        }
    }

    /// Set budget limit
    pub fn set_budget_limit(&mut self, limit: f64) {
        self.budget_limit = Some(limit);
    }
}

impl Default for LlmMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cost_estimation() {
        let monitor = LlmMonitor::new();

        // GPT-4
        let cost = monitor.estimate_cost("gpt-4", 1000, 500);
        assert!((cost - 0.06).abs() < 0.001); // $0.03 input + $0.03 output

        // Claude 3 Haiku
        let cost = monitor.estimate_cost("claude-3-haiku", 1000, 1000);
        assert!((cost - 0.0015).abs() < 0.0001);
    }
}

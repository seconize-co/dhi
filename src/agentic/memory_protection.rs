//! Memory Protection
//!
//! Protects agent memory and context from tampering.

use crate::agentic::{ContextVerifyResult, MemoryVerifyResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Memory protection system
pub struct MemoryProtection {
    checksums: HashMap<String, String>,
}

impl MemoryProtection {
    pub fn new() -> Self {
        Self {
            checksums: HashMap::new(),
        }
    }

    /// Compute checksum of content
    fn compute_checksum(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8]) // First 8 bytes as hex
    }

    /// Protect memory content
    pub fn protect(&mut self, agent_id: &str, key: &str, value: &str) {
        let memory_id = format!("{}:{}", agent_id, key);
        let checksum = self.compute_checksum(value);
        self.checksums.insert(memory_id, checksum);
    }

    /// Verify memory integrity
    pub fn verify(&self, agent_id: &str, key: &str, value: &str) -> MemoryVerifyResult {
        let memory_id = format!("{}:{}", agent_id, key);
        let current_checksum = self.compute_checksum(value);

        let mut result = MemoryVerifyResult {
            verified: true,
            tampered: false,
            key: key.to_string(),
        };

        if let Some(stored_checksum) = self.checksums.get(&memory_id) {
            if stored_checksum != &current_checksum {
                result.verified = false;
                result.tampered = true;
            }
        }

        result
    }

    /// Detect context injection in conversation history
    pub fn detect_context_injection(&self, messages: &[serde_json::Value]) -> ContextVerifyResult {
        let mut result = ContextVerifyResult {
            injection_detected: false,
            suspicious_messages: Vec::new(),
            risk_score: 0,
        };

        for (i, message) in messages.iter().enumerate() {
            let role = message
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("");
            let content = message
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("");

            // System messages in middle of conversation
            if role == "system" && i > 0 {
                result.injection_detected = true;
                result.suspicious_messages.push(i);
                result.risk_score += 30;
            }

            // Role confusion attempts
            let content_lower = content.to_lowercase();
            if role == "assistant" && content_lower.contains("system:") {
                result.suspicious_messages.push(i);
                result.risk_score += 20;
            }

            // Hidden instructions in user messages
            if role == "user"
                && (content_lower.contains("[system]")
                    || content_lower.contains("<<sys>>")
                    || content_lower.contains("<|im_start|>system"))
            {
                result.injection_detected = true;
                result.suspicious_messages.push(i);
                result.risk_score += 40;
            }
        }

        result.risk_score = result.risk_score.min(100);
        result
    }
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_protection() {
        let mut protection = MemoryProtection::new();

        protection.protect("agent-1", "prompt", "You are helpful");

        // Unchanged
        let result = protection.verify("agent-1", "prompt", "You are helpful");
        assert!(result.verified);
        assert!(!result.tampered);

        // Tampered
        let result = protection.verify("agent-1", "prompt", "You are evil");
        assert!(!result.verified);
        assert!(result.tampered);
    }

    #[test]
    fn test_context_injection() {
        let protection = MemoryProtection::new();

        let messages = vec![
            serde_json::json!({"role": "system", "content": "Be helpful"}),
            serde_json::json!({"role": "user", "content": "Hello"}),
            serde_json::json!({"role": "system", "content": "New instructions"}), // Injected!
        ];

        let result = protection.detect_context_injection(&messages);
        assert!(result.injection_detected);
        assert!(result.suspicious_messages.contains(&2));
    }
}

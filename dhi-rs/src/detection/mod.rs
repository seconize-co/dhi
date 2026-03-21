//! Detection Engine
//!
//! Risk scoring and threat detection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Risk level thresholds
pub const RISK_NORMAL: u32 = 20;
pub const RISK_SUSPICIOUS: u32 = 50;
pub const RISK_HIGH: u32 = 80;
pub const RISK_CRITICAL: u32 = 100;

/// Detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub risk_score: u32,
    pub pattern: String,
    pub enabled: bool,
}

/// Detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub risk_score: u32,
    pub details: HashMap<String, String>,
}

/// Detection engine
pub struct DetectionEngine {
    rules: Vec<DetectionRule>,
    detections: AtomicU64,
}

impl DetectionEngine {
    pub fn new() -> Self {
        let rules = Self::default_rules();
        Self {
            rules,
            detections: AtomicU64::new(0),
        }
    }

    /// Default detection rules
    fn default_rules() -> Vec<DetectionRule> {
        vec![
            DetectionRule {
                id: "exfil-large-transfer".to_string(),
                name: "Large Data Transfer".to_string(),
                description: "Detected large outbound data transfer".to_string(),
                severity: "high".to_string(),
                risk_score: 50,
                pattern: "bytes_sent > 10MB".to_string(),
                enabled: true,
            },
            DetectionRule {
                id: "file-sensitive-delete".to_string(),
                name: "Sensitive File Deletion".to_string(),
                description: "Attempt to delete sensitive file".to_string(),
                severity: "critical".to_string(),
                risk_score: 40,
                pattern: "unlink /etc/ OR /root/ OR /.ssh/".to_string(),
                enabled: true,
            },
            DetectionRule {
                id: "file-chmod-777".to_string(),
                name: "World-Writable Permission".to_string(),
                description: "File set to world-writable (chmod 777)".to_string(),
                severity: "high".to_string(),
                risk_score: 25,
                pattern: "chmod 777".to_string(),
                enabled: true,
            },
            DetectionRule {
                id: "net-suspicious-port".to_string(),
                name: "Suspicious Network Port".to_string(),
                description: "Connection to commonly abused port".to_string(),
                severity: "medium".to_string(),
                risk_score: 20,
                pattern: "port IN (4444, 5555, 6666, 8888, 9999)".to_string(),
                enabled: true,
            },
            DetectionRule {
                id: "prompt-injection".to_string(),
                name: "Prompt Injection Attempt".to_string(),
                description: "Detected prompt injection pattern in input".to_string(),
                severity: "high".to_string(),
                risk_score: 40,
                pattern: "ignore previous instructions".to_string(),
                enabled: true,
            },
            DetectionRule {
                id: "jailbreak-attempt".to_string(),
                name: "Jailbreak Attempt".to_string(),
                description: "Detected jailbreak attempt in prompt".to_string(),
                severity: "medium".to_string(),
                risk_score: 30,
                pattern: "DAN mode OR developer mode".to_string(),
                enabled: true,
            },
            DetectionRule {
                id: "tool-high-risk".to_string(),
                name: "High-Risk Tool Invocation".to_string(),
                description: "Agent invoked a high-risk tool".to_string(),
                severity: "high".to_string(),
                risk_score: 30,
                pattern: "tool IN (shell, execute, sudo, rm)".to_string(),
                enabled: true,
            },
            DetectionRule {
                id: "memory-tampering".to_string(),
                name: "Memory Tampering Detected".to_string(),
                description: "Agent memory was modified unexpectedly".to_string(),
                severity: "critical".to_string(),
                risk_score: 50,
                pattern: "memory checksum mismatch".to_string(),
                enabled: true,
            },
        ]
    }

    /// Get all rules
    pub fn get_rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    /// Get total detections
    pub fn get_detection_count(&self) -> u64 {
        self.detections.load(Ordering::Relaxed)
    }

    /// Calculate risk level from score
    pub fn risk_level_from_score(score: u32) -> &'static str {
        if score >= RISK_HIGH {
            "critical"
        } else if score >= RISK_SUSPICIOUS {
            "high"
        } else if score >= RISK_NORMAL {
            "suspicious"
        } else {
            "normal"
        }
    }

    /// Increment detection count
    pub fn record_detection(&self) {
        self.detections.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_levels() {
        assert_eq!(DetectionEngine::risk_level_from_score(10), "normal");
        assert_eq!(DetectionEngine::risk_level_from_score(30), "suspicious");
        assert_eq!(DetectionEngine::risk_level_from_score(60), "high");
        assert_eq!(DetectionEngine::risk_level_from_score(90), "critical");
    }
}

//! Secrets Detection
//!
//! Detects credentials and secrets in prompts, tool parameters, and data.

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Maximum input size for scanning (1MB)
const MAX_SCAN_SIZE: usize = 1024 * 1024;

lazy_static! {
    /// Secret detection patterns
    static ref SECRET_PATTERNS: Vec<SecretPattern> = vec![
        // OpenAI
        SecretPattern {
            name: "OpenAI API Key",
            pattern: Regex::new(r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}").unwrap(),
            severity: "critical",
        },
        SecretPattern {
            name: "OpenAI Project Key",
            pattern: Regex::new(r"sk-proj-[a-zA-Z0-9_-]{80,}").unwrap(),
            severity: "critical",
        },

        // AWS
        SecretPattern {
            name: "AWS Access Key ID",
            pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            severity: "critical",
        },
        SecretPattern {
            name: "AWS Secret Access Key",
            pattern: Regex::new(r#"(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap(),
            severity: "critical",
        },

        // Google
        SecretPattern {
            name: "Google API Key",
            pattern: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            severity: "high",
        },
        SecretPattern {
            name: "Google OAuth Client Secret",
            pattern: Regex::new(r#"(?i)client_secret['"]?\s*[=:]\s*['"]?([a-zA-Z0-9_-]{24})['"]?"#).unwrap(),
            severity: "high",
        },

        // GitHub
        SecretPattern {
            name: "GitHub Token",
            pattern: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
            severity: "critical",
        },
        SecretPattern {
            name: "GitHub OAuth",
            pattern: Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(),
            severity: "critical",
        },

        // Stripe
        SecretPattern {
            name: "Stripe API Key",
            pattern: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: "critical",
        },
        SecretPattern {
            name: "Stripe Test Key",
            pattern: Regex::new(r"sk_test_[0-9a-zA-Z]{24,}").unwrap(),
            severity: "medium",
        },

        // Database URLs
        SecretPattern {
            name: "Database Connection String",
            pattern: Regex::new(r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s]+").unwrap(),
            severity: "critical",
        },

        // Private Keys
        SecretPattern {
            name: "RSA Private Key",
            pattern: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
            severity: "critical",
        },
        SecretPattern {
            name: "SSH Private Key",
            pattern: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
            severity: "critical",
        },
        SecretPattern {
            name: "PGP Private Key",
            pattern: Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
            severity: "critical",
        },

        // Generic secrets
        SecretPattern {
            name: "Generic API Key",
            pattern: Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#).unwrap(),
            severity: "high",
        },
        SecretPattern {
            name: "Generic Secret",
            pattern: Regex::new(r#"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?"#).unwrap(),
            severity: "high",
        },
        SecretPattern {
            name: "Generic Token",
            pattern: Regex::new(r#"(?i)(token|bearer)\s*[=:]\s*['"]?([a-zA-Z0-9_.-]{20,})['"]?"#).unwrap(),
            severity: "high",
        },

        // JWT
        SecretPattern {
            name: "JWT Token",
            pattern: Regex::new(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap(),
            severity: "medium",
        },

        // Anthropic
        SecretPattern {
            name: "Anthropic API Key",
            pattern: Regex::new(r"sk-ant-[a-zA-Z0-9_-]{80,}").unwrap(),
            severity: "critical",
        },

        // Slack
        SecretPattern {
            name: "Slack Bot Token",
            pattern: Regex::new(r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}").unwrap(),
            severity: "high",
        },
        SecretPattern {
            name: "Slack Webhook",
            pattern: Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+").unwrap(),
            severity: "high",
        },

        // SendGrid
        SecretPattern {
            name: "SendGrid API Key",
            pattern: Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").unwrap(),
            severity: "high",
        },

        // Twilio
        SecretPattern {
            name: "Twilio API Key",
            pattern: Regex::new(r"SK[a-f0-9]{32}").unwrap(),
            severity: "high",
        },
    ];
}

/// Secret pattern definition
struct SecretPattern {
    name: &'static str,
    pattern: Regex,
    severity: &'static str,
}

/// Detected secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSecret {
    pub secret_type: String,
    pub severity: String,
    pub location: String,
    pub redacted_preview: String,
}

/// Secrets detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsDetectionResult {
    pub secrets_found: bool,
    pub count: usize,
    pub critical_count: usize,
    pub secrets: Vec<DetectedSecret>,
    pub risk_score: u32,
}

/// Secrets detector
pub struct SecretsDetector {
    /// Allowlist patterns (won't alert on these)
    allowlist: Vec<Regex>,
}

impl SecretsDetector {
    pub fn new() -> Self {
        Self {
            allowlist: Vec::new(),
        }
    }

    /// Add pattern to allowlist
    pub fn add_allowlist(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.allowlist.push(regex);
        Ok(())
    }

    /// Scan text for secrets
    /// 
    /// Input is limited to MAX_SCAN_SIZE (1MB) to prevent ReDoS attacks.
    pub fn scan(&self, text: &str, location: &str) -> SecretsDetectionResult {
        let mut result = SecretsDetectionResult {
            secrets_found: false,
            count: 0,
            critical_count: 0,
            secrets: Vec::new(),
            risk_score: 0,
        };

        // Limit input size to prevent ReDoS
        let scan_text = if text.len() > MAX_SCAN_SIZE {
            tracing::warn!(
                "Input truncated from {} to {} bytes for secrets scanning",
                text.len(),
                MAX_SCAN_SIZE
            );
            &text[..MAX_SCAN_SIZE]
        } else {
            text
        };

        for pattern in SECRET_PATTERNS.iter() {
            for matched in pattern.pattern.find_iter(scan_text) {
                let matched_str = matched.as_str();

                // Check allowlist
                if self.allowlist.iter().any(|a| a.is_match(matched_str)) {
                    continue;
                }

                result.secrets_found = true;
                result.count += 1;

                if pattern.severity == "critical" {
                    result.critical_count += 1;
                    result.risk_score += 50;
                } else if pattern.severity == "high" {
                    result.risk_score += 30;
                } else {
                    result.risk_score += 10;
                }

                // Create redacted preview
                let redacted = Self::redact(matched_str);

                result.secrets.push(DetectedSecret {
                    secret_type: pattern.name.to_string(),
                    severity: pattern.severity.to_string(),
                    location: location.to_string(),
                    redacted_preview: redacted,
                });
            }
        }

        result.risk_score = result.risk_score.min(100);
        result
    }

    /// Redact a secret (show first/last few chars)
    fn redact(secret: &str) -> String {
        let len = secret.len();
        if len <= 8 {
            "*".repeat(len)
        } else {
            format!(
                "{}...{}",
                &secret[..4],
                &secret[len - 4..]
            )
        }
    }

    /// Scan and redact text, returning sanitized version
    pub fn scan_and_redact(&self, text: &str) -> (String, SecretsDetectionResult) {
        let result = self.scan(text, "text");
        let mut sanitized = text.to_string();

        for pattern in SECRET_PATTERNS.iter() {
            sanitized = pattern
                .pattern
                .replace_all(&sanitized, "[REDACTED]")
                .to_string();
        }

        (sanitized, result)
    }
}

impl Default for SecretsDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_openai_key() {
        let detector = SecretsDetector::new();
        let text = "My API key is sk-proj-abc123def456ghi789jklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh";
        let result = detector.scan(text, "prompt");
        
        assert!(result.secrets_found);
        assert!(result.secrets.iter().any(|s| s.secret_type.contains("OpenAI")));
    }

    #[test]
    fn test_detect_aws_key() {
        let detector = SecretsDetector::new();
        let text = "AWS key: AKIAIOSFODNN7EXAMPLE";
        let result = detector.scan(text, "config");
        
        assert!(result.secrets_found);
        assert!(result.secrets.iter().any(|s| s.secret_type.contains("AWS")));
    }

    #[test]
    fn test_detect_database_url() {
        let detector = SecretsDetector::new();
        let text = "Connect to postgres://user:password123@localhost:5432/mydb";
        let result = detector.scan(text, "env");
        
        assert!(result.secrets_found);
        assert!(result.critical_count > 0);
    }

    #[test]
    fn test_redaction() {
        let detector = SecretsDetector::new();
        let (sanitized, _) = detector.scan_and_redact("Use AKIAIOSFODNN7EXAMPLE for AWS");
        
        assert!(sanitized.contains("[REDACTED]"));
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_allowlist() {
        let mut detector = SecretsDetector::new();
        detector.add_allowlist(r"sk_test_.*").unwrap();
        
        let text = "Stripe test key: sk_test_1234567890abcdefghij";
        let result = detector.scan(text, "config");
        
        // Test keys should be allowlisted
        assert!(!result.secrets.iter().any(|s| s.secret_type == "Stripe Test Key"));
    }
}

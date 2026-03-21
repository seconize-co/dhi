//! Data Protection Module
//!
//! Combines secrets detection, PII detection, and auto-redaction.

use super::{PiiDetector, PiiDetectionResult, SecretsDetector, SecretsDetectionResult};
use serde::{Deserialize, Serialize};

/// Combined data protection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProtectionResult {
    pub secrets: SecretsDetectionResult,
    pub pii: PiiDetectionResult,
    pub total_risk_score: u32,
    pub should_block: bool,
    pub redacted_text: Option<String>,
}

/// Data protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProtectionConfig {
    /// Enable secrets detection
    pub detect_secrets: bool,
    /// Enable PII detection
    pub detect_pii: bool,
    /// Auto-redact detected data
    pub auto_redact: bool,
    /// Block on critical secrets
    pub block_on_secrets: bool,
    /// Block on critical PII (SSN, credit cards)
    pub block_on_critical_pii: bool,
    /// Risk score threshold for blocking
    pub block_threshold: u32,
    /// Maximum records allowed per request
    pub max_records_per_request: Option<usize>,
    /// Maximum bytes per external request
    pub max_bytes_external: Option<usize>,
}

impl Default for DataProtectionConfig {
    fn default() -> Self {
        Self {
            detect_secrets: true,
            detect_pii: true,
            auto_redact: true,
            block_on_secrets: true,
            block_on_critical_pii: true,
            block_threshold: 50,
            max_records_per_request: Some(100),
            max_bytes_external: Some(1024 * 1024), // 1MB
        }
    }
}

/// Data protection engine
pub struct DataProtection {
    config: DataProtectionConfig,
    secrets_detector: SecretsDetector,
    pii_detector: PiiDetector,
}

impl DataProtection {
    pub fn new(config: DataProtectionConfig) -> Self {
        Self {
            config,
            secrets_detector: SecretsDetector::new(),
            pii_detector: PiiDetector::new(),
        }
    }

    /// Scan text for sensitive data
    pub fn scan(&self, text: &str, location: &str) -> DataProtectionResult {
        let secrets = if self.config.detect_secrets {
            self.secrets_detector.scan(text, location)
        } else {
            SecretsDetectionResult {
                secrets_found: false,
                count: 0,
                critical_count: 0,
                secrets: vec![],
                risk_score: 0,
            }
        };

        let pii = if self.config.detect_pii {
            self.pii_detector.scan(text, location)
        } else {
            PiiDetectionResult {
                pii_found: false,
                total_count: 0,
                critical_count: 0,
                pii_types: vec![],
                risk_score: 0,
            }
        };

        let total_risk_score = (secrets.risk_score + pii.risk_score).min(100);

        // Determine if we should block
        let should_block = self.should_block(&secrets, &pii, total_risk_score);

        // Auto-redact if configured
        let redacted_text = if self.config.auto_redact && (secrets.secrets_found || pii.pii_found) {
            Some(self.redact(text))
        } else {
            None
        };

        DataProtectionResult {
            secrets,
            pii,
            total_risk_score,
            should_block,
            redacted_text,
        }
    }

    /// Determine if request should be blocked
    fn should_block(
        &self,
        secrets: &SecretsDetectionResult,
        pii: &PiiDetectionResult,
        total_risk_score: u32,
    ) -> bool {
        // Block on critical secrets
        if self.config.block_on_secrets && secrets.critical_count > 0 {
            return true;
        }

        // Block on critical PII
        if self.config.block_on_critical_pii && pii.critical_count > 0 {
            return true;
        }

        // Block if risk score exceeds threshold
        if total_risk_score >= self.config.block_threshold {
            return true;
        }

        false
    }

    /// Redact all sensitive data from text
    pub fn redact(&self, text: &str) -> String {
        let mut redacted = text.to_string();

        // Redact secrets first
        let (secret_redacted, _) = self.secrets_detector.scan_and_redact(&redacted);
        redacted = secret_redacted;

        // Then redact PII
        redacted = self.pii_detector.redact(&redacted);

        redacted
    }

    /// Check data egress limits
    pub fn check_egress(
        &self,
        text: &str,
        destination: &str,
        is_external: bool,
    ) -> EgressCheckResult {
        let byte_size = text.len();
        let estimated_records = self.pii_detector.estimate_record_count(text);

        let mut violations = Vec::new();

        // Check byte limit for external destinations
        if is_external {
            if let Some(max_bytes) = self.config.max_bytes_external {
                if byte_size > max_bytes {
                    violations.push(format!(
                        "Payload size {} bytes exceeds limit {} bytes for external destination",
                        byte_size, max_bytes
                    ));
                }
            }
        }

        // Check record count
        if let Some(max_records) = self.config.max_records_per_request {
            if estimated_records > max_records {
                violations.push(format!(
                    "Estimated {} records exceeds limit {} per request",
                    estimated_records, max_records
                ));
            }
        }

        EgressCheckResult {
            allowed: violations.is_empty(),
            byte_size,
            estimated_records,
            destination: destination.to_string(),
            is_external,
            violations,
        }
    }

    /// Add pattern to secrets allowlist
    pub fn allowlist_secret_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        self.secrets_detector.add_allowlist(pattern)
    }

    /// Ignore certain PII types
    pub fn ignore_pii_type(&mut self, pii_type: &str) {
        self.pii_detector.ignore(pii_type);
    }
}

/// Egress check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressCheckResult {
    pub allowed: bool,
    pub byte_size: usize,
    pub estimated_records: usize,
    pub destination: String,
    pub is_external: bool,
    pub violations: Vec<String>,
}

impl Default for DataProtection {
    fn default() -> Self {
        Self::new(DataProtectionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_detection() {
        let protection = DataProtection::default();

        let text = "Contact john@example.com, SSN: 123-45-6789, API key: sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh";
        let result = protection.scan(text, "prompt");

        assert!(result.secrets.secrets_found);
        assert!(result.pii.pii_found);
        assert!(result.should_block); // Critical data found
        assert!(result.redacted_text.is_some());
    }

    #[test]
    fn test_redaction() {
        let protection = DataProtection::default();

        let text = "Email: john@example.com, Password: secret123";
        let redacted = protection.redact(text);

        assert!(!redacted.contains("john@example.com"));
        assert!(!redacted.contains("secret123"));
        assert!(redacted.contains("[EMAIL]") || redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_egress_limits() {
        let protection = DataProtection::new(DataProtectionConfig {
            max_bytes_external: Some(100),
            max_records_per_request: Some(2),
            ..Default::default()
        });

        // Small payload - allowed
        let result = protection.check_egress("small data", "api.external.com", true);
        assert!(result.allowed);

        // Large payload - blocked
        let large = "x".repeat(200);
        let result = protection.check_egress(&large, "api.external.com", true);
        assert!(!result.allowed);
        assert!(result.violations.iter().any(|v| v.contains("bytes")));
    }
}

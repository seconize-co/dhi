//! PII Detector
//!
//! Detects Personally Identifiable Information in agent communications.

#![allow(clippy::unwrap_used)]
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Maximum input size for scanning (1MB)
const MAX_SCAN_SIZE: usize = 1024 * 1024;

lazy_static! {
    /// PII detection patterns
    static ref PII_PATTERNS: Vec<PiiPattern> = vec![
        // Email
        PiiPattern {
            pii_type: "email",
            pattern: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
            severity: "medium",
            redact_format: "[EMAIL]",
        },

        // Phone numbers (various formats)
        PiiPattern {
            pii_type: "phone",
            pattern: Regex::new(r"\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b").unwrap(),
            severity: "medium",
            redact_format: "[PHONE]",
        },

        // SSN
        PiiPattern {
            pii_type: "ssn",
            pattern: Regex::new(r"\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b").unwrap(),
            severity: "critical",
            redact_format: "[SSN]",
        },

        // Credit card (Visa, Mastercard, Amex, Discover)
        PiiPattern {
            pii_type: "credit_card",
            pattern: Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap(),
            severity: "critical",
            redact_format: "[CREDIT_CARD]",
        },

        // Date of birth (various formats)
        PiiPattern {
            pii_type: "dob",
            pattern: Regex::new(r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)[0-9]{2}\b").unwrap(),
            severity: "medium",
            redact_format: "[DOB]",
        },

        // IP Address
        PiiPattern {
            pii_type: "ip_address",
            pattern: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            severity: "low",
            redact_format: "[IP]",
        },

        // Passport (US format)
        PiiPattern {
            pii_type: "passport",
            pattern: Regex::new(r"\b[A-Z][0-9]{8}\b").unwrap(),
            severity: "critical",
            redact_format: "[PASSPORT]",
        },

        // Driver's License (generic pattern)
        PiiPattern {
            pii_type: "drivers_license",
            pattern: Regex::new(r"(?i)\b(?:DL|driver'?s?\s*license)[:\s#]*[A-Z0-9]{6,12}\b").unwrap(),
            severity: "high",
            redact_format: "[DL]",
        },

        // Bank Account (generic)
        PiiPattern {
            pii_type: "bank_account",
            pattern: Regex::new(r"(?i)\b(?:account|acct)[:\s#]*[0-9]{8,17}\b").unwrap(),
            severity: "high",
            redact_format: "[BANK_ACCT]",
        },

        // Routing Number
        PiiPattern {
            pii_type: "routing_number",
            pattern: Regex::new(r"(?i)\b(?:routing|aba)[:\s#]*[0-9]{9}\b").unwrap(),
            severity: "high",
            redact_format: "[ROUTING]",
        },

        // Medicare/Medicaid ID
        PiiPattern {
            pii_type: "medicare_id",
            pattern: Regex::new(r"\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}[A-Z]?\b").unwrap(),
            severity: "critical",
            redact_format: "[MEDICARE]",
        },

        // Address (street pattern)
        PiiPattern {
            pii_type: "address",
            pattern: Regex::new(r"\b\d{1,5}\s+[\w\s]{1,30}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\b").unwrap(),
            severity: "medium",
            redact_format: "[ADDRESS]",
        },

        // ZIP code
        PiiPattern {
            pii_type: "zip_code",
            pattern: Regex::new(r"\b[0-9]{5}(?:-[0-9]{4})?\b").unwrap(),
            severity: "low",
            redact_format: "[ZIP]",
        },
    ];
}

/// PII pattern definition
struct PiiPattern {
    pii_type: &'static str,
    pattern: Regex,
    severity: &'static str,
    redact_format: &'static str,
}

/// Detected PII instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPii {
    pub pii_type: String,
    pub severity: String,
    pub count: usize,
    pub locations: Vec<String>,
}

/// PII detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDetectionResult {
    pub pii_found: bool,
    pub total_count: usize,
    pub critical_count: usize,
    pub pii_types: Vec<DetectedPii>,
    pub risk_score: u32,
}

/// PII detector
pub struct PiiDetector {
    /// Types to ignore
    ignore_types: Vec<String>,
}

impl PiiDetector {
    pub fn new() -> Self {
        Self {
            ignore_types: Vec::new(),
        }
    }

    /// Ignore certain PII types
    pub fn ignore(&mut self, pii_type: &str) {
        self.ignore_types.push(pii_type.to_string());
    }

    /// Scan text for PII
    ///
    /// Input is limited to MAX_SCAN_SIZE (1MB) to prevent ReDoS attacks.
    pub fn scan(&self, text: &str, location: &str) -> PiiDetectionResult {
        let mut result = PiiDetectionResult {
            pii_found: false,
            total_count: 0,
            critical_count: 0,
            pii_types: Vec::new(),
            risk_score: 0,
        };

        // Limit input size to prevent ReDoS
        let scan_text = if text.len() > MAX_SCAN_SIZE {
            tracing::warn!(
                "Input truncated from {} to {} bytes for PII scanning",
                text.len(),
                MAX_SCAN_SIZE
            );
            &text[..MAX_SCAN_SIZE]
        } else {
            text
        };

        let mut type_counts: std::collections::HashMap<&str, (usize, &str, Vec<String>)> =
            std::collections::HashMap::new();

        for pattern in PII_PATTERNS.iter() {
            if self.ignore_types.contains(&pattern.pii_type.to_string()) {
                continue;
            }

            let matches: Vec<_> = pattern.pattern.find_iter(scan_text).collect();
            if !matches.is_empty() {
                let entry = type_counts
                    .entry(pattern.pii_type)
                    .or_insert((0, pattern.severity, Vec::new()));
                entry.0 += matches.len();
                entry.2.push(location.to_string());
            }
        }

        for (pii_type, (count, severity, locations)) in type_counts {
            result.pii_found = true;
            result.total_count += count;

            match severity {
                "critical" => {
                    result.critical_count += count;
                    result.risk_score += count as u32 * 40;
                }
                "high" => {
                    result.risk_score += count as u32 * 25;
                }
                "medium" => {
                    result.risk_score += count as u32 * 15;
                }
                _ => {
                    result.risk_score += count as u32 * 5;
                }
            }

            result.pii_types.push(DetectedPii {
                pii_type: pii_type.to_string(),
                severity: severity.to_string(),
                count,
                locations,
            });
        }

        result.risk_score = result.risk_score.min(100);
        result
    }

    /// Redact PII from text
    pub fn redact(&self, text: &str) -> String {
        let mut redacted = text.to_string();

        for pattern in PII_PATTERNS.iter() {
            if self.ignore_types.contains(&pattern.pii_type.to_string()) {
                continue;
            }
            redacted = pattern
                .pattern
                .replace_all(&redacted, pattern.redact_format)
                .to_string();
        }

        redacted
    }

    /// Scan and redact in one operation
    pub fn scan_and_redact(&self, text: &str, location: &str) -> (String, PiiDetectionResult) {
        let result = self.scan(text, location);
        let redacted = self.redact(text);
        (redacted, result)
    }

    /// Estimate record count from payload
    pub fn estimate_record_count(&self, text: &str) -> usize {
        // Count potential records based on PII occurrences
        let email_count = PII_PATTERNS[0].pattern.find_iter(text).count();
        let phone_count = PII_PATTERNS[1].pattern.find_iter(text).count();
        let ssn_count = PII_PATTERNS[2].pattern.find_iter(text).count();

        // Use the maximum as record estimate
        email_count.max(phone_count).max(ssn_count).max(1)
    }
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_email() {
        let detector = PiiDetector::new();
        let text = "Contact me at john.doe@example.com for more info";
        let result = detector.scan(text, "prompt");

        assert!(result.pii_found);
        assert!(result.pii_types.iter().any(|p| p.pii_type == "email"));
    }

    #[test]
    fn test_detect_ssn() {
        let detector = PiiDetector::new();
        let text = "SSN: 123-45-6789";
        let result = detector.scan(text, "data");

        assert!(result.pii_found);
        assert!(result.critical_count > 0);
        assert!(result.pii_types.iter().any(|p| p.pii_type == "ssn"));
    }

    #[test]
    fn test_detect_credit_card() {
        let detector = PiiDetector::new();
        let text = "Card number: 4532015112830366";
        let result = detector.scan(text, "payment");

        assert!(result.pii_found);
        assert!(result.pii_types.iter().any(|p| p.pii_type == "credit_card"));
    }

    #[test]
    fn test_redaction() {
        let detector = PiiDetector::new();
        let text = "Email: john@example.com, SSN: 123-45-6789";
        let redacted = detector.redact(text);

        assert!(redacted.contains("[EMAIL]"));
        assert!(redacted.contains("[SSN]"));
        assert!(!redacted.contains("john@example.com"));
    }

    #[test]
    fn test_multiple_pii() {
        let detector = PiiDetector::new();
        let text = "John Doe, john@example.com, 555-123-4567, SSN: 123-45-6789, Card: 4532015112830366";
        let result = detector.scan(text, "customer_record");

        assert!(result.pii_found);
        assert!(result.total_count >= 4);
        assert!(result.critical_count >= 2); // SSN and credit card
    }

    #[test]
    fn test_record_estimation() {
        let detector = PiiDetector::new();
        let text = r#"
            user1@example.com, 123-45-6789
            user2@example.com, 234-56-7890
            user3@example.com, 345-67-8901
        "#;
        let count = detector.estimate_record_count(text);
        assert_eq!(count, 3);
    }
}
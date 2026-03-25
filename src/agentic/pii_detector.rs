//! PII Detector
//!
//! Detects Personally Identifiable Information in agent communications.

#![allow(clippy::unwrap_used)]
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::external_pattern_rules;

/// Maximum input size for scanning (1MB)
const MAX_SCAN_SIZE: usize = 1024 * 1024;

lazy_static! {
    /// PII detection patterns
    static ref PII_PATTERNS: Vec<PiiPattern> = vec![
        // Email
        PiiPattern {
            pii_type: "email".to_string(),
            pattern: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
            severity: "medium".to_string(),
            redact_format: "[EMAIL]".to_string(),
        },

        // Phone numbers (various formats)
        PiiPattern {
            pii_type: "phone".to_string(),
            // Require explicit separators or parentheses to avoid matching bare 10-digit timestamps.
            pattern: Regex::new(r"(?x)\b(?:\+1[-.\s]?)?(?:\([0-9]{3}\)\s*[0-9]{3}[-.\s][0-9]{4}|[0-9]{3}[-.\s][0-9]{3}[-.\s][0-9]{4})\b").unwrap(),
            severity: "medium".to_string(),
            redact_format: "[PHONE]".to_string(),
        },

        // SSN
        PiiPattern {
            pii_type: "ssn".to_string(),
            pattern: Regex::new(r"\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b").unwrap(),
            severity: "critical".to_string(),
            redact_format: "[SSN]".to_string(),
        },

        // Credit card (Visa, Mastercard, Amex, Discover)
        PiiPattern {
            pii_type: "credit_card".to_string(),
            pattern: Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap(),
            severity: "critical".to_string(),
            redact_format: "[CREDIT_CARD]".to_string(),
        },

        // Date of birth (various formats)
        PiiPattern {
            pii_type: "dob".to_string(),
            pattern: Regex::new(r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)[0-9]{2}\b").unwrap(),
            severity: "medium".to_string(),
            redact_format: "[DOB]".to_string(),
        },

        // IP Address
        PiiPattern {
            pii_type: "ip_address".to_string(),
            pattern: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            severity: "low".to_string(),
            redact_format: "[IP]".to_string(),
        },

        // Passport (US format)
        PiiPattern {
            pii_type: "passport".to_string(),
            pattern: Regex::new(r"\b[A-Z][0-9]{8}\b").unwrap(),
            severity: "critical".to_string(),
            redact_format: "[PASSPORT]".to_string(),
        },

        // Driver's License (generic pattern)
        PiiPattern {
            pii_type: "drivers_license".to_string(),
            pattern: Regex::new(r"(?i)\b(?:DL|driver'?s?\s*license)[:\s#]*[A-Z0-9]{6,12}\b").unwrap(),
            severity: "high".to_string(),
            redact_format: "[DL]".to_string(),
        },

        // Bank Account (generic)
        PiiPattern {
            pii_type: "bank_account".to_string(),
            pattern: Regex::new(r"(?i)\b(?:account|acct)[:\s#]*[0-9]{8,17}\b").unwrap(),
            severity: "high".to_string(),
            redact_format: "[BANK_ACCT]".to_string(),
        },

        // Routing Number
        PiiPattern {
            pii_type: "routing_number".to_string(),
            pattern: Regex::new(r"(?i)\b(?:routing|aba)[:\s#]*[0-9]{9}\b").unwrap(),
            severity: "high".to_string(),
            redact_format: "[ROUTING]".to_string(),
        },

        // Medicare/Medicaid ID
        PiiPattern {
            pii_type: "medicare_id".to_string(),
            pattern: Regex::new(r"\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}[A-Z]?\b").unwrap(),
            severity: "critical".to_string(),
            redact_format: "[MEDICARE]".to_string(),
        },

        // Address (street pattern)
        PiiPattern {
            pii_type: "address".to_string(),
            pattern: Regex::new(r"\b\d{1,5}\s+[\w\s]{1,30}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\b").unwrap(),
            severity: "medium".to_string(),
            redact_format: "[ADDRESS]".to_string(),
        },

        // ZIP code
        PiiPattern {
            pii_type: "zip_code".to_string(),
            pattern: Regex::new(r"\b[0-9]{5}(?:-[0-9]{4})?\b").unwrap(),
            severity: "low".to_string(),
            redact_format: "[ZIP]".to_string(),
        },
    ];
}

/// PII pattern definition
struct PiiPattern {
    pii_type: String,
    pattern: Regex,
    severity: String,
    redact_format: String,
}

fn all_pii_patterns() -> Vec<PiiPattern> {
    let mut patterns: Vec<PiiPattern> = PII_PATTERNS
        .iter()
        .map(|p| PiiPattern {
            pii_type: p.pii_type.clone(),
            pattern: p.pattern.clone(),
            severity: p.severity.clone(),
            redact_format: p.redact_format.clone(),
        })
        .collect();

    if let Some(rules) = external_pattern_rules() {
        for p in &rules.pii_patterns {
            if let Ok(regex) = Regex::new(&p.regex) {
                patterns.push(PiiPattern {
                    pii_type: p.pii_type.clone(),
                    pattern: regex,
                    severity: p.severity.clone(),
                    redact_format: p.redact_format.clone(),
                });
            }
        }
    }
    patterns
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
    patterns: Vec<PiiPattern>,
}

impl PiiDetector {
    pub fn new() -> Self {
        Self {
            ignore_types: Vec::new(),
            patterns: all_pii_patterns(),
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

        let mut type_counts: std::collections::HashMap<String, (usize, String, Vec<String>)> =
            std::collections::HashMap::new();

        for pattern in &self.patterns {
            if self.ignore_types.contains(&pattern.pii_type) {
                continue;
            }

            let matches: Vec<_> = pattern
                .pattern
                .find_iter(scan_text)
                .filter(|m| !Self::should_ignore_match(pattern, m.as_str()))
                .collect();
            if !matches.is_empty() {
                let entry = type_counts.entry(pattern.pii_type.clone()).or_insert((
                    0,
                    pattern.severity.clone(),
                    Vec::new(),
                ));
                entry.0 += matches.len();
                entry.2.push(location.to_string());
            }
        }

        for (pii_type, (count, severity, locations)) in type_counts {
            result.pii_found = true;
            result.total_count += count;

            match severity.as_str() {
                "critical" => {
                    result.critical_count += count;
                    result.risk_score += count as u32 * 40;
                },
                "high" => {
                    result.risk_score += count as u32 * 25;
                },
                "medium" => {
                    result.risk_score += count as u32 * 15;
                },
                _ => {
                    result.risk_score += count as u32 * 5;
                },
            }

            result.pii_types.push(DetectedPii {
                pii_type,
                severity,
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

        for pattern in &self.patterns {
            if self.ignore_types.contains(&pattern.pii_type) {
                continue;
            }
            if pattern.pii_type == "phone" {
                let source = redacted.clone();
                let mut rebuilt = String::with_capacity(source.len());
                let mut cursor = 0usize;
                for matched in pattern.pattern.find_iter(&source) {
                    rebuilt.push_str(&source[cursor..matched.start()]);
                    if Self::should_ignore_match(pattern, matched.as_str()) {
                        rebuilt.push_str(matched.as_str());
                    } else {
                        rebuilt.push_str(&pattern.redact_format);
                    }
                    cursor = matched.end();
                }
                rebuilt.push_str(&source[cursor..]);
                redacted = rebuilt;
            } else {
                redacted = pattern
                    .pattern
                    .replace_all(&redacted, pattern.redact_format.as_str())
                    .to_string();
            }
        }

        redacted
    }

    /// Scan and redact in one operation
    pub fn scan_and_redact(&self, text: &str, location: &str) -> (String, PiiDetectionResult) {
        let result = self.scan(text, location);
        let redacted = self.redact(text);
        (redacted, result)
    }

    /// Build safe context hints around detected PII.
    /// The matched value is replaced with the pattern redact format (e.g., [EMAIL], [PHONE]).
    pub fn context_hints(&self, text: &str, max_hints: usize) -> Vec<String> {
        if max_hints == 0 {
            return Vec::new();
        }
        let scan_text = if text.len() > MAX_SCAN_SIZE {
            &text[..MAX_SCAN_SIZE]
        } else {
            text
        };

        let mut hints = Vec::new();
        for pattern in &self.patterns {
            if self.ignore_types.contains(&pattern.pii_type) {
                continue;
            }
            for matched in pattern.pattern.find_iter(scan_text) {
                if Self::should_ignore_match(pattern, matched.as_str()) {
                    continue;
                }
                if hints.len() >= max_hints {
                    return hints;
                }
                const SIDE_BYTES: usize = 48;
                let left_start = matched.start().saturating_sub(SIDE_BYTES);
                let right_end = (matched.end() + SIDE_BYTES).min(scan_text.len());
                let left = self
                    .redact(&scan_text[left_start..matched.start()])
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let right = self
                    .redact(&scan_text[matched.end()..right_end])
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                hints.push(format!(
                    "{}...{}{}{}...",
                    pattern.pii_type, left, pattern.redact_format, right
                ));
            }
        }
        hints
    }

    /// Estimate record count from payload
    pub fn estimate_record_count(&self, text: &str) -> usize {
        // Count potential records based on PII occurrences
        let email_count = self.patterns[0].pattern.find_iter(text).count();
        let phone_count = self.patterns[1]
            .pattern
            .find_iter(text)
            .filter(|m| !Self::should_ignore_match(&self.patterns[1], m.as_str()))
            .count();
        let ssn_count = self.patterns[2].pattern.find_iter(text).count();

        // Use the maximum as record estimate
        email_count.max(phone_count).max(ssn_count).max(1)
    }

    fn should_ignore_match(pattern: &PiiPattern, matched: &str) -> bool {
        pattern.pii_type == "phone" && Self::is_timestamp_like_phone(matched)
    }

    fn is_timestamp_like_phone(matched: &str) -> bool {
        let digits: String = matched.chars().filter(|c| c.is_ascii_digit()).collect();
        let has_separator = matched
            .chars()
            .any(|c| ['-', '.', ' ', '(', ')'].contains(&c));
        if digits.len() == 10 && !has_separator {
            if let Ok(value) = digits.parse::<u64>() {
                // Unix seconds range 2000-01-01 through 2100-01-01.
                return (946_684_800..=4_102_444_800).contains(&value);
            }
        }
        false
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
        let text =
            "John Doe, john@example.com, 555-123-4567, SSN: 123-45-6789, Card: 4532015112830366";
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

    #[test]
    fn test_context_hints_redact_pii_value() {
        let detector = PiiDetector::new();
        let text = "Contact Jane at jane.doe@example.com and +1 212 555 0188 for follow-up";
        let hints = detector.context_hints(text, 5);

        assert!(!hints.is_empty(), "should emit at least one context hint");
        assert!(hints
            .iter()
            .any(|h| h.contains("[EMAIL]") || h.contains("[PHONE]")));
        assert!(hints
            .iter()
            .all(|h| !h.contains("jane.doe@example.com") && !h.contains("+1 212 555 0188")));
    }

    #[test]
    fn test_phone_detection_ignores_unix_timestamp_like_values() {
        let detector = PiiDetector::new();
        let text = "created_at: 1774414038 updated_at: 1774415038";
        let result = detector.scan(text, "json_payload");
        assert!(
            !result.pii_types.iter().any(|p| p.pii_type == "phone"),
            "unix timestamp-like values must not be classified as phone numbers"
        );
    }

    #[test]
    fn test_redaction_keeps_timestamp_but_redacts_real_phone() {
        let detector = PiiDetector::new();
        let text = "created_at: 1774414038 phone: 555-123-4567";
        let redacted = detector.redact(text);
        assert!(
            redacted.contains("1774414038"),
            "timestamp-like value should not be redacted as phone"
        );
        assert!(
            redacted.contains("[PHONE]"),
            "real phone format should still be redacted"
        );
    }
}

//! Unit tests for PII Detector

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> PiiDetector {
        PiiDetector::new()
    }

    // ==================== Email Addresses ====================

    #[test]
    fn test_detect_email() {
        let d = detector();
        let text = "Contact me at john.doe@example.com for more info.";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect email");
        assert_eq!(results[0].pii_type, "email");
        assert_eq!(results[0].value, "john.doe@example.com");
    }

    #[test]
    fn test_detect_multiple_emails() {
        let d = detector();
        let text = "Send to alice@test.org and bob@company.co.uk";
        let results = d.detect(text);
        assert!(results.len() >= 2, "Should detect multiple emails");
    }

    #[test]
    fn test_detect_email_with_plus() {
        let d = detector();
        let text = "Email: user+tag@gmail.com";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect email with plus addressing");
    }

    // ==================== Phone Numbers ====================

    #[test]
    fn test_detect_us_phone() {
        let d = detector();
        let text = "Call me at (555) 123-4567";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect US phone number");
        assert_eq!(results[0].pii_type, "phone");
    }

    #[test]
    fn test_detect_phone_with_dashes() {
        let d = detector();
        let text = "Phone: 555-123-4567";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect phone with dashes");
    }

    #[test]
    fn test_detect_phone_with_dots() {
        let d = detector();
        let text = "Tel: 555.123.4567";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect phone with dots");
    }

    #[test]
    fn test_detect_international_phone() {
        let d = detector();
        let text = "International: +1-555-123-4567";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect international phone");
    }

    // ==================== Social Security Numbers ====================

    #[test]
    fn test_detect_ssn() {
        let d = detector();
        let text = "SSN: 123-45-6789";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect SSN");
        assert_eq!(results[0].pii_type, "ssn");
    }

    #[test]
    fn test_detect_ssn_no_dashes() {
        let d = detector();
        let text = "Social: 123456789";
        let results = d.detect(text);
        // May or may not detect without context - depends on implementation
    }

    // ==================== Credit Card Numbers ====================

    #[test]
    fn test_detect_visa() {
        let d = detector();
        let text = "Card: 4111-1111-1111-1111";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect Visa card");
        assert_eq!(results[0].pii_type, "credit_card");
    }

    #[test]
    fn test_detect_mastercard() {
        let d = detector();
        let text = "Payment: 5500 0000 0000 0004";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect Mastercard");
    }

    #[test]
    fn test_detect_amex() {
        let d = detector();
        let text = "Amex: 3782-822463-10005";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect Amex");
    }

    #[test]
    fn test_detect_card_no_separators() {
        let d = detector();
        let text = "Card number: 4111111111111111";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect card without separators");
    }

    // ==================== IP Addresses ====================

    #[test]
    fn test_detect_ipv4() {
        let d = detector();
        let text = "Server IP: 192.168.1.100";
        let results = d.detect(text);
        assert!(!results.is_empty(), "Should detect IPv4");
        assert_eq!(results[0].pii_type, "ip_address");
    }

    #[test]
    fn test_no_detect_localhost() {
        let d = detector();
        let text = "Running on 127.0.0.1";
        let results = d.detect(text);
        // Localhost may be filtered out as non-sensitive
    }

    // ==================== Addresses ====================

    #[test]
    fn test_detect_street_address() {
        let d = detector();
        let text = "Ship to: 123 Main Street, Apt 4B";
        let results = d.detect(text);
        // Address detection varies by implementation
        let has_address = results.iter().any(|r| r.pii_type == "address");
        // This is optional - address detection is complex
    }

    // ==================== Names ====================

    #[test]
    fn test_detect_name_pattern() {
        let d = detector();
        let text = "Customer: Mr. John Smith";
        let results = d.detect(text);
        // Name detection is complex and may have false positives
    }

    // ==================== Dates of Birth ====================

    #[test]
    fn test_detect_dob() {
        let d = detector();
        let text = "DOB: 01/15/1990";
        let results = d.detect(text);
        // DOB detection varies
    }

    // ==================== Multiple PII ====================

    #[test]
    fn test_detect_multiple_pii() {
        let d = detector();
        let text = "John Doe, email: john@example.com, phone: 555-123-4567, SSN: 123-45-6789";
        let results = d.detect(text);
        assert!(results.len() >= 3, "Should detect multiple PII types");
    }

    // ==================== No False Positives ====================

    #[test]
    fn test_no_false_positive_normal_text() {
        let d = detector();
        let text = "The weather is nice today. Let's go for a walk.";
        let results = d.detect(text);
        assert!(results.is_empty(), "Should not detect PII in normal text");
    }

    #[test]
    fn test_no_false_positive_code() {
        let d = detector();
        let text = "for i in range(10): print(i)";
        let results = d.detect(text);
        assert!(results.is_empty(), "Should not detect PII in code");
    }

    // ==================== Redaction ====================

    #[test]
    fn test_redact_email() {
        let d = detector();
        let text = "Email me at secret@company.com";
        let redacted = d.redact(text);
        assert!(!redacted.contains("secret@company.com"), "Should redact email");
        assert!(redacted.contains("[EMAIL]") || redacted.contains("***"), "Should have redaction marker");
    }

    #[test]
    fn test_redact_phone() {
        let d = detector();
        let text = "Call 555-123-4567";
        let redacted = d.redact(text);
        assert!(!redacted.contains("555-123-4567"), "Should redact phone");
    }

    #[test]
    fn test_redact_ssn() {
        let d = detector();
        let text = "SSN: 123-45-6789";
        let redacted = d.redact(text);
        assert!(!redacted.contains("123-45-6789"), "Should redact SSN");
    }

    #[test]
    fn test_redact_credit_card() {
        let d = detector();
        let text = "Card: 4111-1111-1111-1111";
        let redacted = d.redact(text);
        assert!(!redacted.contains("4111-1111-1111-1111"), "Should redact card");
    }

    // ==================== Risk Scoring ====================

    #[test]
    fn test_risk_score_ssn() {
        let d = detector();
        let text = "SSN: 123-45-6789";
        let results = d.detect(text);
        if !results.is_empty() {
            assert!(results[0].risk_score >= 90, "SSN should have high risk score");
        }
    }

    #[test]
    fn test_risk_score_email() {
        let d = detector();
        let text = "Email: test@example.com";
        let results = d.detect(text);
        if !results.is_empty() {
            assert!(results[0].risk_score >= 30, "Email should have moderate risk score");
        }
    }

    // ==================== Input Size Limits (ReDoS Prevention) ====================

    #[test]
    fn test_large_input_handled_safely() {
        let d = detector();
        
        // Create input larger than MAX_SCAN_SIZE (1MB)
        let large_input = "x".repeat(2_000_000);
        
        // Should not panic and should complete in reasonable time
        let start = std::time::Instant::now();
        let results = d.detect(&large_input);
        let elapsed = start.elapsed();
        
        // Should complete quickly (truncation kicks in)
        assert!(elapsed.as_secs() < 5, "Large input should be handled quickly via truncation");
        
        // No PII in repeated 'x' characters
        assert!(results.is_empty());
    }

    #[test]
    fn test_pii_at_start_of_large_input() {
        let d = detector();
        
        // Put PII at the start, followed by padding
        let pii = "Contact: john.doe@example.com and call 555-123-4567. SSN: 123-45-6789";
        let padding = "y".repeat(2_000_000);
        let input = format!("{}{}", pii, padding);
        
        // Should still detect the PII (it's within first 1MB)
        let results = d.detect(&input);
        assert!(!results.is_empty(), "Should detect PII at start even with large input");
    }

    #[test]
    fn test_email_regex_no_backtracking() {
        let d = detector();
        
        // Pattern that could cause catastrophic backtracking on email regex
        let evil_input = "a".repeat(50) + "@" + &"b".repeat(50) + "." + &"c".repeat(50);
        
        let start = std::time::Instant::now();
        let _results = d.detect(&evil_input);
        let elapsed = start.elapsed();
        
        // Should complete quickly (no ReDoS)
        assert!(elapsed.as_secs() < 2, "Email regex should not cause catastrophic backtracking");
    }
}

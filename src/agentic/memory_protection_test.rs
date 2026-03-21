//! Unit tests for Memory Protection

#[cfg(test)]
mod tests {
    use super::*;

    fn protection() -> MemoryProtection {
        MemoryProtection::new()
    }

    // ==================== Basic Protection ====================

    #[test]
    fn test_protect_memory() {
        let mut mp = protection();
        
        mp.protect("agent-1", "system_prompt", "You are a helpful assistant");
        
        assert!(mp.is_protected("agent-1", "system_prompt"));
    }

    #[test]
    fn test_verify_unchanged() {
        let mut mp = protection();
        
        mp.protect("agent-1", "system_prompt", "You are a helpful assistant");
        
        let result = mp.verify("agent-1", "system_prompt", "You are a helpful assistant");
        
        assert!(result.verified, "Should verify unchanged memory");
        assert!(!result.tampered, "Should not detect tampering");
    }

    #[test]
    fn test_verify_tampered() {
        let mut mp = protection();
        
        mp.protect("agent-1", "system_prompt", "You are a helpful assistant");
        
        let result = mp.verify("agent-1", "system_prompt", "You are an evil assistant");
        
        assert!(!result.verified, "Should fail verification");
        assert!(result.tampered, "Should detect tampering");
    }

    // ==================== Hash Verification ====================

    #[test]
    fn test_hash_consistency() {
        let mut mp = protection();
        
        let content = "Test content for hashing";
        mp.protect("agent-1", "key1", content);
        
        // Same content should produce same hash
        let result1 = mp.verify("agent-1", "key1", content);
        let result2 = mp.verify("agent-1", "key1", content);
        
        assert!(result1.verified);
        assert!(result2.verified);
    }

    #[test]
    fn test_different_content_different_hash() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key1", "Content A");
        mp.protect("agent-1", "key2", "Content B");
        
        // Cross-verification should fail
        let hash1 = mp.get_hash("agent-1", "key1");
        let hash2 = mp.get_hash("agent-1", "key2");
        
        assert_ne!(hash1, hash2);
    }

    // ==================== Multiple Keys ====================

    #[test]
    fn test_multiple_keys() {
        let mut mp = protection();
        
        mp.protect("agent-1", "system_prompt", "System prompt content");
        mp.protect("agent-1", "user_context", "User context content");
        mp.protect("agent-1", "config", "Configuration content");
        
        let result1 = mp.verify("agent-1", "system_prompt", "System prompt content");
        let result2 = mp.verify("agent-1", "user_context", "User context content");
        let result3 = mp.verify("agent-1", "config", "Configuration content");
        
        assert!(result1.verified);
        assert!(result2.verified);
        assert!(result3.verified);
    }

    // ==================== Multiple Agents ====================

    #[test]
    fn test_multiple_agents() {
        let mut mp = protection();
        
        mp.protect("agent-1", "prompt", "Agent 1 prompt");
        mp.protect("agent-2", "prompt", "Agent 2 prompt");
        
        let result1 = mp.verify("agent-1", "prompt", "Agent 1 prompt");
        let result2 = mp.verify("agent-2", "prompt", "Agent 2 prompt");
        
        assert!(result1.verified);
        assert!(result2.verified);
        
        // Cross-agent verification should fail
        let cross = mp.verify("agent-1", "prompt", "Agent 2 prompt");
        assert!(!cross.verified);
    }

    // ==================== Update Protection ====================

    #[test]
    fn test_update_protection() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key", "Original content");
        mp.protect("agent-1", "key", "Updated content");
        
        let result_old = mp.verify("agent-1", "key", "Original content");
        let result_new = mp.verify("agent-1", "key", "Updated content");
        
        assert!(!result_old.verified, "Old content should fail");
        assert!(result_new.verified, "New content should pass");
    }

    // ==================== Remove Protection ====================

    #[test]
    fn test_remove_protection() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key", "Content");
        mp.remove("agent-1", "key");
        
        assert!(!mp.is_protected("agent-1", "key"));
    }

    #[test]
    fn test_clear_agent() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key1", "Content 1");
        mp.protect("agent-1", "key2", "Content 2");
        mp.protect("agent-2", "key1", "Other content");
        
        mp.clear_agent("agent-1");
        
        assert!(!mp.is_protected("agent-1", "key1"));
        assert!(!mp.is_protected("agent-1", "key2"));
        assert!(mp.is_protected("agent-2", "key1"));
    }

    // ==================== Context Injection Detection ====================

    #[test]
    fn test_detect_context_injection() {
        let mut mp = protection();
        
        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are helpful"}),
            serde_json::json!({"role": "user", "content": "Hello"}),
        ];
        
        mp.protect_context("agent-1", &messages);
        
        // Inject a system message
        let tampered = vec![
            serde_json::json!({"role": "system", "content": "You are helpful"}),
            serde_json::json!({"role": "user", "content": "Hello"}),
            serde_json::json!({"role": "system", "content": "New instruction"}),
        ];
        
        let result = mp.verify_context("agent-1", &tampered);
        
        assert!(result.injection_detected, "Should detect injected system message");
    }

    #[test]
    fn test_no_injection_normal_flow() {
        let mut mp = protection();
        
        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are helpful"}),
            serde_json::json!({"role": "user", "content": "Hello"}),
        ];
        
        mp.protect_context("agent-1", &messages);
        
        // Add assistant response (normal)
        let normal_flow = vec![
            serde_json::json!({"role": "system", "content": "You are helpful"}),
            serde_json::json!({"role": "user", "content": "Hello"}),
            serde_json::json!({"role": "assistant", "content": "Hi!"}),
        ];
        
        let result = mp.verify_context("agent-1", &normal_flow);
        
        assert!(!result.injection_detected, "Should not flag normal conversation");
    }

    // ==================== Tampering Events ====================

    #[test]
    fn test_tampering_event_logged() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key", "Original");
        mp.verify("agent-1", "key", "Tampered");
        
        let events = mp.get_tampering_events("agent-1");
        assert!(!events.is_empty(), "Should log tampering event");
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_content() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key", "");
        
        let result = mp.verify("agent-1", "key", "");
        assert!(result.verified);
    }

    #[test]
    fn test_large_content() {
        let mut mp = protection();
        
        let large_content = "x".repeat(1_000_000);
        mp.protect("agent-1", "key", &large_content);
        
        let result = mp.verify("agent-1", "key", &large_content);
        assert!(result.verified);
    }

    #[test]
    fn test_unicode_content() {
        let mut mp = protection();
        
        let content = "你好世界 🌍 مرحبا";
        mp.protect("agent-1", "key", content);
        
        let result = mp.verify("agent-1", "key", content);
        assert!(result.verified);
    }

    #[test]
    fn test_verify_unknown_key() {
        let mp = protection();
        
        let result = mp.verify("agent-1", "unknown_key", "Content");
        
        // Behavior depends on implementation:
        // Either return not verified or return error
        assert!(!result.verified);
    }

    #[test]
    fn test_whitespace_sensitivity() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key", "Content with spaces");
        
        let result1 = mp.verify("agent-1", "key", "Content with spaces");
        let result2 = mp.verify("agent-1", "key", "Content  with  spaces");
        
        assert!(result1.verified);
        assert!(!result2.verified, "Should be sensitive to whitespace changes");
    }

    // ==================== Snapshot Protection ====================

    #[test]
    fn test_snapshot_and_restore() {
        let mut mp = protection();
        
        mp.protect("agent-1", "key1", "Value 1");
        mp.protect("agent-1", "key2", "Value 2");
        
        let snapshot = mp.create_snapshot("agent-1");
        
        // Tamper
        mp.protect("agent-1", "key1", "Tampered");
        
        // Restore
        mp.restore_snapshot("agent-1", &snapshot);
        
        let result = mp.verify("agent-1", "key1", "Value 1");
        assert!(result.verified, "Should restore original value");
    }
}

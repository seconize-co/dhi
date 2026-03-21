//! Unit tests for MCP Monitor

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn monitor() -> McpMonitor {
        McpMonitor::new()
    }

    // ==================== Message Parsing ====================

    #[test]
    fn test_parse_tool_call() {
        let m = monitor();
        
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "filesystem_read",
                "arguments": {"path": "/tmp/test.txt"}
            },
            "id": 1
        });
        
        let parsed = m.parse_message(&msg);
        
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.method, "tools/call");
        assert_eq!(parsed.tool_name, Some("filesystem_read".to_string()));
    }

    #[test]
    fn test_parse_tool_list() {
        let m = monitor();
        
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        
        let parsed = m.parse_message(&msg);
        
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().method, "tools/list");
    }

    #[test]
    fn test_parse_resource_read() {
        let m = monitor();
        
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {
                "uri": "file:///etc/passwd"
            },
            "id": 1
        });
        
        let parsed = m.parse_message(&msg);
        
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.method, "resources/read");
    }

    #[test]
    fn test_parse_prompt_get() {
        let m = monitor();
        
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "prompts/get",
            "params": {
                "name": "summarize"
            },
            "id": 1
        });
        
        let parsed = m.parse_message(&msg);
        
        assert!(parsed.is_ok());
    }

    // ==================== Risk Assessment ====================

    #[test]
    fn test_assess_safe_tool() {
        let m = monitor();
        
        let msg = json!({
            "method": "tools/call",
            "params": {
                "name": "calculator",
                "arguments": {"expression": "2+2"}
            }
        });
        
        let result = m.assess_risk(&msg);
        
        assert!(result.risk_score < 30);
        assert!(result.allowed);
    }

    #[test]
    fn test_assess_filesystem_read_sensitive() {
        let m = monitor();
        
        let msg = json!({
            "method": "tools/call",
            "params": {
                "name": "filesystem_read",
                "arguments": {"path": "/etc/shadow"}
            }
        });
        
        let result = m.assess_risk(&msg);
        
        assert!(result.risk_score >= 80);
        assert!(!result.allowed);
    }

    #[test]
    fn test_assess_shell_execute() {
        let m = monitor();
        
        let msg = json!({
            "method": "tools/call",
            "params": {
                "name": "shell_execute",
                "arguments": {"command": "rm -rf /"}
            }
        });
        
        let result = m.assess_risk(&msg);
        
        assert!(result.risk_score >= 90);
        assert!(!result.allowed);
    }

    #[test]
    fn test_assess_network_suspicious_port() {
        let m = monitor();
        
        let msg = json!({
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "http://evil.com:4444/exfil"
                }
            }
        });
        
        let result = m.assess_risk(&msg);
        
        assert!(result.risk_score >= 70);
    }

    // ==================== Response Analysis ====================

    #[test]
    fn test_analyze_response_with_secrets() {
        let m = monitor();
        
        let response = json!({
            "result": {
                "content": "API key is sk-proj-abc123def456ghi789"
            }
        });
        
        let result = m.analyze_response(&response);
        
        assert!(result.contains_secrets);
        assert!(result.risk_score >= 80);
    }

    #[test]
    fn test_analyze_response_with_pii() {
        let m = monitor();
        
        let response = json!({
            "result": {
                "content": "User email: john@example.com, SSN: 123-45-6789"
            }
        });
        
        let result = m.analyze_response(&response);
        
        assert!(result.contains_pii);
    }

    #[test]
    fn test_analyze_safe_response() {
        let m = monitor();
        
        let response = json!({
            "result": {
                "content": "The weather today is sunny with a high of 75°F"
            }
        });
        
        let result = m.analyze_response(&response);
        
        assert!(!result.contains_secrets);
        assert!(!result.contains_pii);
        assert!(result.risk_score < 20);
    }

    // ==================== Session Tracking ====================

    #[test]
    fn test_track_session() {
        let m = monitor();
        
        m.start_session("session-1", "agent-1");
        
        m.record_message("session-1", json!({"method": "tools/list"}));
        m.record_message("session-1", json!({"method": "tools/call", "params": {"name": "search"}}));
        
        let stats = m.get_session_stats("session-1");
        
        assert_eq!(stats.message_count, 2);
        assert_eq!(stats.tool_calls, 1);
    }

    #[test]
    fn test_session_tool_usage() {
        let m = monitor();
        
        m.start_session("session-1", "agent-1");
        
        m.record_message("session-1", json!({
            "method": "tools/call",
            "params": {"name": "search"}
        }));
        m.record_message("session-1", json!({
            "method": "tools/call",
            "params": {"name": "search"}
        }));
        m.record_message("session-1", json!({
            "method": "tools/call",
            "params": {"name": "calculator"}
        }));
        
        let usage = m.get_tool_usage("session-1");
        
        assert_eq!(usage.get("search"), Some(&2));
        assert_eq!(usage.get("calculator"), Some(&1));
    }

    // ==================== Protocol Validation ====================

    #[test]
    fn test_validate_jsonrpc_format() {
        let m = monitor();
        
        let valid = json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        
        let invalid = json!({
            "method": "tools/list"
            // missing jsonrpc version
        });
        
        assert!(m.validate_format(&valid).is_ok());
        assert!(m.validate_format(&invalid).is_err());
    }

    #[test]
    fn test_validate_method() {
        let m = monitor();
        
        let valid_methods = ["tools/list", "tools/call", "resources/read", "prompts/get"];
        
        for method in valid_methods {
            let msg = json!({"jsonrpc": "2.0", "method": method, "id": 1});
            assert!(m.validate_method(&msg).is_ok());
        }
    }

    // ==================== Capability Tracking ====================

    #[test]
    fn test_track_capabilities() {
        let m = monitor();
        
        let capabilities = json!({
            "tools": [
                {"name": "search", "description": "Search the web"},
                {"name": "calculator", "description": "Do math"}
            ]
        });
        
        m.register_capabilities("server-1", &capabilities);
        
        let caps = m.get_capabilities("server-1");
        assert!(caps.tools.contains(&"search".to_string()));
        assert!(caps.tools.contains(&"calculator".to_string()));
    }

    // ==================== Allowlist/Denylist ====================

    #[test]
    fn test_tool_allowlist() {
        let mut m = monitor();
        
        m.set_tool_allowlist(vec!["search".to_string(), "calculator".to_string()]);
        
        let allowed = json!({"method": "tools/call", "params": {"name": "search"}});
        let denied = json!({"method": "tools/call", "params": {"name": "shell"}});
        
        assert!(m.assess_risk(&allowed).allowed);
        assert!(!m.assess_risk(&denied).allowed);
    }

    #[test]
    fn test_tool_denylist() {
        let mut m = monitor();
        
        m.set_tool_denylist(vec!["shell".to_string(), "dangerous".to_string()]);
        
        let msg = json!({"method": "tools/call", "params": {"name": "shell"}});
        
        assert!(!m.assess_risk(&msg).allowed);
    }

    // ==================== Rate Limiting ====================

    #[test]
    fn test_rate_limit_detection() {
        let m = monitor();
        
        m.start_session("session-1", "agent-1");
        
        // Rapid tool calls
        for _ in 0..100 {
            m.record_message("session-1", json!({
                "method": "tools/call",
                "params": {"name": "api"}
            }));
        }
        
        let stats = m.get_session_stats("session-1");
        assert!(stats.rate_limit_triggered);
    }

    // ==================== Error Handling ====================

    #[test]
    fn test_handle_error_response() {
        let m = monitor();
        
        let error = json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            },
            "id": 1
        });
        
        let result = m.analyze_response(&error);
        assert!(result.is_error);
    }

    #[test]
    fn test_handle_malformed_message() {
        let m = monitor();
        
        let malformed = json!("not an object");
        
        let result = m.parse_message(&malformed);
        assert!(result.is_err());
    }

    // ==================== Statistics ====================

    #[test]
    fn test_global_stats() {
        let m = monitor();
        
        m.start_session("s1", "a1");
        m.start_session("s2", "a2");
        
        m.record_message("s1", json!({"method": "tools/call", "params": {"name": "t1"}}));
        m.record_message("s2", json!({"method": "tools/call", "params": {"name": "t2"}}));
        
        let stats = m.get_global_stats();
        
        assert_eq!(stats.active_sessions, 2);
        assert_eq!(stats.total_tool_calls, 2);
    }
}

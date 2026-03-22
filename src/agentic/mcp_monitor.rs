//! MCP Monitor
//!
//! Monitors Model Context Protocol communications.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MCP message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMessage {
    pub jsonrpc: String,
    pub method: Option<String>,
    pub id: Option<serde_json::Value>,
    pub params: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<serde_json::Value>,
}

/// MCP method categories
#[derive(Debug, Clone)]
pub enum McpMethodCategory {
    Handshake,
    Discovery,
    Invocation,
    Access,
    LlmCall,
    Unknown,
}

/// MCP Monitor
pub struct McpMonitor {
    method_categories: HashMap<String, McpMethodCategory>,
    pub active_sessions: HashMap<String, McpSession>,
}

/// MCP session state
#[derive(Debug, Clone, Default)]
pub struct McpSession {
    pub session_id: String,
    pub initialized: bool,
    pub available_tools: Vec<String>,
    pub tool_invocations: u64,
    pub resource_accesses: u64,
}

impl McpMonitor {
    pub fn new() -> Self {
        let mut method_categories = HashMap::new();

        // Map methods to categories
        method_categories.insert("initialize".to_string(), McpMethodCategory::Handshake);
        method_categories.insert("tools/list".to_string(), McpMethodCategory::Discovery);
        method_categories.insert("tools/call".to_string(), McpMethodCategory::Invocation);
        method_categories.insert("resources/list".to_string(), McpMethodCategory::Discovery);
        method_categories.insert("resources/read".to_string(), McpMethodCategory::Access);
        method_categories.insert("prompts/list".to_string(), McpMethodCategory::Discovery);
        method_categories.insert("prompts/get".to_string(), McpMethodCategory::Access);
        method_categories.insert(
            "sampling/createMessage".to_string(),
            McpMethodCategory::LlmCall,
        );

        Self {
            method_categories,
            active_sessions: HashMap::new(),
        }
    }

    /// Parse MCP JSON-RPC message
    pub fn parse_message(&self, data: &[u8]) -> Option<McpMessage> {
        serde_json::from_slice(data).ok()
    }

    /// Get category for a method
    pub fn get_method_category(&self, method: &str) -> McpMethodCategory {
        self.method_categories
            .get(method)
            .cloned()
            .unwrap_or(McpMethodCategory::Unknown)
    }

    /// Track a session
    pub fn track_session(&mut self, session_id: &str) -> &mut McpSession {
        self.active_sessions
            .entry(session_id.to_string())
            .or_insert_with(|| McpSession {
                session_id: session_id.to_string(),
                ..Default::default()
            })
    }

    /// Extract tool name from MCP tool call
    pub fn extract_tool_name(&self, params: &serde_json::Value) -> Option<String> {
        params
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
    }

    /// Extract tool arguments from MCP tool call
    pub fn extract_tool_args(&self, params: &serde_json::Value) -> serde_json::Value {
        params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}))
    }
}

impl Default for McpMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mcp_message() {
        let monitor = McpMonitor::new();

        let data =
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{}}}"#;
        let msg = monitor.parse_message(data);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.method, Some("tools/call".to_string()));
    }

    #[test]
    fn test_extract_tool_name() {
        let monitor = McpMonitor::new();

        let params = serde_json::json!({
            "name": "web_search",
            "arguments": {"query": "test"}
        });

        assert_eq!(
            monitor.extract_tool_name(&params),
            Some("web_search".to_string())
        );
    }
}

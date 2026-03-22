//! Tool Monitor
//!
//! Monitors tool invocations with risk analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// High-risk tool patterns
const HIGH_RISK_TOOLS: &[&str] = &[
    "shell",
    "bash",
    "execute",
    "run_command",
    "terminal",
    "write_file",
    "delete_file",
    "modify_file",
    "http_request",
    "fetch",
    "curl",
    "sql_query",
    "database",
    "send_email",
    "notify",
];

/// Sensitive path patterns
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/",
    "/.ssh/",
    "/root/",
    "/home/",
    ".env",
    "password",
    "secret",
    "token",
    "api_key",
    "credential",
    "private_key",
];

/// Command injection patterns
const INJECTION_PATTERNS: &[&str] = &[";", "&&", "||", "`", "$(", "${", "|"];

/// Tool risk analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRiskAnalysis {
    pub tool_name: String,
    pub risk_level: String,
    pub risk_score: u32,
    pub flags: Vec<String>,
}

/// Tool monitor
pub struct ToolMonitor {
    denylist: HashSet<String>,
    allowlist: HashSet<String>,
}

impl ToolMonitor {
    pub fn new() -> Self {
        let mut denylist = HashSet::new();
        denylist.insert("sudo".to_string());
        denylist.insert("rm -rf".to_string());
        denylist.insert("chmod 777".to_string());
        denylist.insert("curl | bash".to_string());
        denylist.insert("wget | sh".to_string());

        Self {
            denylist,
            allowlist: HashSet::new(),
        }
    }

    /// Analyze a tool call for risk
    pub fn analyze_tool_call(
        &self,
        tool_name: &str,
        parameters: &serde_json::Value,
    ) -> ToolRiskAnalysis {
        let mut result = ToolRiskAnalysis {
            tool_name: tool_name.to_string(),
            risk_level: "low".to_string(),
            risk_score: 0,
            flags: Vec::new(),
        };

        let tool_lower = tool_name.to_lowercase();

        // Check for high-risk tools
        for risky in HIGH_RISK_TOOLS {
            if tool_lower.contains(risky) {
                result.risk_score += 30;
                result.flags.push(format!("high_risk_tool:{}", risky));
            }
        }

        // Analyze parameters
        let params_str = parameters.to_string().to_lowercase();

        // Check for sensitive paths
        for path in SENSITIVE_PATHS {
            if params_str.contains(path) {
                result.risk_score += 25;
                result.flags.push(format!("sensitive_path:{}", path));
            }
        }

        // Check for external network access
        if params_str.contains("http://")
            || params_str.contains("https://")
            || params_str.contains("ftp://")
        {
            result.risk_score += 15;
            result.flags.push("external_network".to_string());
        }

        // Check for command injection patterns
        for pattern in INJECTION_PATTERNS {
            if params_str.contains(pattern) {
                result.risk_score += 40;
                result.flags.push("potential_injection".to_string());
                break;
            }
        }

        // Determine risk level
        result.risk_level = if result.risk_score >= 50 {
            "critical".to_string()
        } else if result.risk_score >= 30 {
            "high".to_string()
        } else if result.risk_score >= 15 {
            "medium".to_string()
        } else {
            "low".to_string()
        };

        result
    }

    /// Check if tool is denied
    pub fn is_denied(&self, tool_name: &str) -> bool {
        let tool_lower = tool_name.to_lowercase();
        self.denylist
            .iter()
            .any(|d| tool_lower.contains(&d.to_lowercase()))
    }

    /// Check if tool is allowed (when allowlist is active)
    pub fn is_allowed(&self, tool_name: &str) -> bool {
        if self.allowlist.is_empty() {
            return true; // No allowlist means all allowed
        }
        self.allowlist.contains(tool_name)
    }

    /// Add tool to denylist
    pub fn deny(&mut self, pattern: &str) {
        self.denylist.insert(pattern.to_string());
    }

    /// Add tool to allowlist
    pub fn allow(&mut self, tool_name: &str) {
        self.allowlist.insert(tool_name.to_string());
    }
}

impl Default for ToolMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_risk_tool() {
        let monitor = ToolMonitor::new();
        let result =
            monitor.analyze_tool_call("shell_execute", &serde_json::json!({"command": "ls"}));
        assert!(result.risk_score >= 30);
        assert!(result.flags.iter().any(|f| f.contains("high_risk_tool")));
    }

    #[test]
    fn test_sensitive_path() {
        let monitor = ToolMonitor::new();
        let result =
            monitor.analyze_tool_call("read_file", &serde_json::json!({"path": "/etc/passwd"}));
        assert!(result.risk_score >= 25);
        assert!(result.flags.iter().any(|f| f.contains("sensitive_path")));
    }

    #[test]
    fn test_denied_tool() {
        let monitor = ToolMonitor::new();
        assert!(monitor.is_denied("sudo rm"));
        assert!(monitor.is_denied("rm -rf /"));
        assert!(!monitor.is_denied("web_search"));
    }
}

use super::{ExtractedSession, RequestInfo, SessionType};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) fn derive_process_context_session(
    request: &RequestInfo,
    copilot_like: bool,
) -> Option<ExtractedSession> {
    let pid = request.pid?;
    let process_name = request
        .process_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let cwd_suffix = std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown-cwd".to_string());

    let tty_suffix = std::fs::read_link(format!("/proc/{pid}/fd/0"))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|v| v.contains("/dev/"))
        .unwrap_or_else(|| "no-tty".to_string());

    let derived_session_name = read_session_name_from_environ(pid)
        .or_else(|| read_copilot_workspace_name(pid))
        .or_else(|| read_tmux_session_name(&tty_suffix).map(|s| format!("tmux:{s}")))
        .unwrap_or_else(|| format!("{process_name}@{cwd_suffix} ({tty_suffix})"));

    let (session_type, prefix) = if copilot_like {
        (
            SessionType::Custom("CopilotProcess".to_string()),
            "copilot-process",
        )
    } else {
        (
            SessionType::Custom("ProcessContext".to_string()),
            "process-session",
        )
    };

    Some(ExtractedSession {
        session_id: format!("{prefix}:{pid}"),
        session_type,
        session_name: Some(derived_session_name),
    })
}

pub(super) fn read_session_name_from_environ(pid: u32) -> Option<String> {
    let data = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    let candidates = [
        "DHI_SESSION_NAME=",
        "COPILOT_SESSION_NAME=",
        "AGENT_SESSION_NAME=",
        "SESSION_NAME=",
    ];
    for entry in data.split(|b| *b == 0) {
        let Ok(text) = std::str::from_utf8(entry) else {
            continue;
        };
        for key in candidates {
            if let Some(value) = text.strip_prefix(key) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

pub(super) fn read_tmux_session_name(tty: &str) -> Option<String> {
    if !tty.starts_with("/dev/pts/") {
        return None;
    }
    let output = Command::new("tmux")
        .args(["display-message", "-p", "-t", tty, "#S"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub(super) fn read_copilot_workspace_name(pid: u32) -> Option<String> {
    let home_dir = read_home_from_environ(pid)
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_else(|| "/home/sashank".to_string());
    let base = PathBuf::from(home_dir).join(".copilot/session-state");
    read_copilot_workspace_name_from(&base, pid)
}

pub(super) fn read_home_from_environ(pid: u32) -> Option<String> {
    let data = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    for entry in data.split(|b| *b == 0) {
        let Ok(text) = std::str::from_utf8(entry) else {
            continue;
        };
        if let Some(home) = text.strip_prefix("HOME=") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub(super) fn read_copilot_workspace_name_from(
    session_state_base: &Path,
    pid: u32,
) -> Option<String> {
    let entries = std::fs::read_dir(session_state_base).ok()?;
    let lock_name = format!("inuse.{pid}.lock");
    for entry in entries.filter_map(Result::ok) {
        let dir_path = entry.path();
        if !dir_path.is_dir() {
            continue;
        }
        if !dir_path.join(&lock_name).exists() {
            continue;
        }
        let workspace_path = dir_path.join("workspace.yaml");
        let Ok(content) = std::fs::read_to_string(workspace_path) else {
            continue;
        };
        if let Some(name) = extract_workspace_yaml_name(&content) {
            return Some(name);
        }
    }
    None
}

pub(super) fn extract_workspace_yaml_name(content: &str) -> Option<String> {
    let mut summary: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(v) = trimmed.strip_prefix("name:") {
            let name = v.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
        if let Some(v) = trimmed.strip_prefix("summary:") {
            let s = v.trim();
            if !s.is_empty() {
                summary = Some(s.to_string());
            }
        }
    }
    summary
}

pub(super) fn derive_session_name(
    session_id: &str,
    session_type: &SessionType,
    headers: &HashMap<String, String>,
    body_json: Option<&serde_json::Value>,
) -> Option<String> {
    let header_name_keys = [
        "x-session-name",
        "session-name",
        "x-conversation-name",
        "conversation-name",
        "x-thread-name",
        "thread-name",
        "x-run-name",
        "run-name",
    ];

    for (key, value) in headers {
        let key_lower = key.to_ascii_lowercase();
        if header_name_keys.contains(&key_lower.as_str()) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    if let Some(json) = body_json {
        let root_keys = [
            "session_name",
            "conversation_name",
            "thread_name",
            "run_name",
            "name",
        ];
        for key in root_keys {
            if let Some(name) = json.get(key).and_then(|v| v.as_str()) {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        if let Some(metadata) = json.get("metadata") {
            for key in root_keys {
                if let Some(name) = metadata.get(key).and_then(|v| v.as_str()) {
                    let trimmed = name.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }

    let prefix = match session_type {
        SessionType::ClaudeConversation => "conversation",
        SessionType::LangChainRun => "run",
        SessionType::LangChainTrace => "trace",
        SessionType::TraceId => "trace",
        SessionType::OpenAIRequest => "openai-request",
        SessionType::AnthropicRequest => "anthropic-request",
        SessionType::Custom(name) => name,
    };
    Some(format!("{prefix}:{session_id}"))
}

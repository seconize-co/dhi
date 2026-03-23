use super::{ExtractedSession, RequestInfo, SessionType};

const MAX_EXTRACTED_SESSIONS_PER_REQUEST: usize = 64;
const MAX_SESSION_ID_LEN: usize = 256;

fn normalize_session_id(session_id: &str) -> Option<String> {
    let trimmed = session_id.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_SESSION_ID_LEN {
        return None;
    }
    Some(trimmed.to_string())
}

fn push_session(
    out: &mut Vec<ExtractedSession>,
    session_id: &str,
    session_type: SessionType,
    session_name: Option<String>,
) {
    if out.len() >= MAX_EXTRACTED_SESSIONS_PER_REQUEST {
        return;
    }
    let Some(normalized_id) = normalize_session_id(session_id) else {
        return;
    };
    out.push(ExtractedSession {
        session_id: normalized_id,
        session_type,
        session_name,
    });
}

pub(super) fn extract_header_sessions(request: &RequestInfo, out: &mut Vec<ExtractedSession>) {
    const LANGCHAIN_RUN_KEYS: &[&str] = &[
        "x-langchain-run-id",
        "langchain-run-id",
        "x-langchain-session-id",
        "langchain-session-id",
    ];
    const LANGCHAIN_TRACE_KEYS: &[&str] = &["x-langchain-trace-id", "langchain-trace-id"];
    const TRACE_KEYS: &[&str] = &["x-trace-id", "trace-id", "traceparent"];
    const SESSION_KEYS: &[&str] = &["x-session-id", "session-id"];
    const CONVERSATION_KEYS: &[&str] = &["x-conversation-id", "conversation-id"];

    for (key, value) in &request.headers {
        let key_lower = key.to_ascii_lowercase();

        if LANGCHAIN_RUN_KEYS.contains(&key_lower.as_str()) {
            push_session(out, value, SessionType::LangChainRun, None);
            continue;
        }
        if LANGCHAIN_TRACE_KEYS.contains(&key_lower.as_str()) {
            push_session(out, value, SessionType::LangChainTrace, None);
            continue;
        }
        if key_lower == "x-request-id" && request.hostname.contains("openai") {
            push_session(out, value, SessionType::OpenAIRequest, None);
            continue;
        }
        if key_lower == "x-request-id" && request.hostname.contains("anthropic") {
            push_session(out, value, SessionType::AnthropicRequest, None);
            continue;
        }
        if TRACE_KEYS.contains(&key_lower.as_str()) {
            push_session(out, value, SessionType::TraceId, None);
            continue;
        }
        if SESSION_KEYS.contains(&key_lower.as_str()) {
            push_session(out, value, SessionType::Custom("Session".to_string()), None);
            continue;
        }
        if CONVERSATION_KEYS.contains(&key_lower.as_str()) {
            push_session(out, value, SessionType::ClaudeConversation, None);
        }
    }
}

pub(super) fn extract_body_sessions(json: &serde_json::Value, out: &mut Vec<ExtractedSession>) {
    if let Some(metadata) = json.get("metadata") {
        if let Some(conv_id) = metadata.get("conversation_id").and_then(|v| v.as_str()) {
            push_session(out, conv_id, SessionType::ClaudeConversation, None);
        }
        if let Some(session_id) = metadata.get("session_id").and_then(|v| v.as_str()) {
            push_session(
                out,
                session_id,
                SessionType::Custom("Session".to_string()),
                None,
            );
        }
        if let Some(run_id) = metadata.get("run_id").and_then(|v| v.as_str()) {
            push_session(out, run_id, SessionType::LangChainRun, None);
        }
    }

    if let Some(run_id) = json.get("run_id").and_then(|v| v.as_str()) {
        push_session(out, run_id, SessionType::LangChainRun, None);
    }

    if let Some(thread_id) = json.get("thread_id").and_then(|v| v.as_str()) {
        push_session(
            out,
            thread_id,
            SessionType::Custom("Thread".to_string()),
            None,
        );
    }

    for key in [
        "sessionId",
        "agent_session_id",
        "agentSessionId",
        "conversationId",
    ] {
        if let Some(session_id) = json.get(key).and_then(|v| v.as_str()) {
            push_session(
                out,
                session_id,
                SessionType::Custom("AgentSession".to_string()),
                None,
            );
        }
    }

    if let Some(metadata) = json.get("metadata") {
        for key in [
            "sessionId",
            "agent_session_id",
            "agentSessionId",
            "conversationId",
        ] {
            if let Some(session_id) = metadata.get(key).and_then(|v| v.as_str()) {
                push_session(
                    out,
                    session_id,
                    SessionType::Custom("AgentSession".to_string()),
                    None,
                );
            }
        }
    }
}

pub(super) fn extract_run_marker_sessions(body: &str, out: &mut Vec<ExtractedSession>) {
    let mut idx = 0usize;
    let marker = "RUN-";
    while let Some(pos) = body[idx..].find(marker) {
        let start = idx + pos;
        let tail = &body[start..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(tail.len());
        let run_id = &tail[..end];
        if run_id.len() > 4 {
            push_session(
                out,
                run_id,
                SessionType::Custom("RunMarker".to_string()),
                Some(format!("copilot-run:{run_id}")),
            );
        }
        idx = start.saturating_add(end);
        if idx >= body.len() {
            break;
        }
    }
}

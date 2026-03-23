use super::{ExtractedSession, RequestInfo, SessionType};

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
            out.push(ExtractedSession {
                session_id: value.to_string(),
                session_type: SessionType::LangChainRun,
                session_name: None,
            });
            continue;
        }
        if LANGCHAIN_TRACE_KEYS.contains(&key_lower.as_str()) {
            out.push(ExtractedSession {
                session_id: value.to_string(),
                session_type: SessionType::LangChainTrace,
                session_name: None,
            });
            continue;
        }
        if key_lower == "x-request-id" && request.hostname.contains("openai") {
            out.push(ExtractedSession {
                session_id: value.to_string(),
                session_type: SessionType::OpenAIRequest,
                session_name: None,
            });
            continue;
        }
        if key_lower == "x-request-id" && request.hostname.contains("anthropic") {
            out.push(ExtractedSession {
                session_id: value.to_string(),
                session_type: SessionType::AnthropicRequest,
                session_name: None,
            });
            continue;
        }
        if TRACE_KEYS.contains(&key_lower.as_str()) {
            out.push(ExtractedSession {
                session_id: value.to_string(),
                session_type: SessionType::TraceId,
                session_name: None,
            });
            continue;
        }
        if SESSION_KEYS.contains(&key_lower.as_str()) {
            out.push(ExtractedSession {
                session_id: value.to_string(),
                session_type: SessionType::Custom("Session".to_string()),
                session_name: None,
            });
            continue;
        }
        if CONVERSATION_KEYS.contains(&key_lower.as_str()) {
            out.push(ExtractedSession {
                session_id: value.to_string(),
                session_type: SessionType::ClaudeConversation,
                session_name: None,
            });
        }
    }
}

pub(super) fn extract_body_sessions(json: &serde_json::Value, out: &mut Vec<ExtractedSession>) {
    if let Some(metadata) = json.get("metadata") {
        if let Some(conv_id) = metadata.get("conversation_id").and_then(|v| v.as_str()) {
            out.push(ExtractedSession {
                session_id: conv_id.to_string(),
                session_type: SessionType::ClaudeConversation,
                session_name: None,
            });
        }
        if let Some(session_id) = metadata.get("session_id").and_then(|v| v.as_str()) {
            out.push(ExtractedSession {
                session_id: session_id.to_string(),
                session_type: SessionType::Custom("Session".to_string()),
                session_name: None,
            });
        }
        if let Some(run_id) = metadata.get("run_id").and_then(|v| v.as_str()) {
            out.push(ExtractedSession {
                session_id: run_id.to_string(),
                session_type: SessionType::LangChainRun,
                session_name: None,
            });
        }
    }

    if let Some(run_id) = json.get("run_id").and_then(|v| v.as_str()) {
        out.push(ExtractedSession {
            session_id: run_id.to_string(),
            session_type: SessionType::LangChainRun,
            session_name: None,
        });
    }

    if let Some(thread_id) = json.get("thread_id").and_then(|v| v.as_str()) {
        out.push(ExtractedSession {
            session_id: thread_id.to_string(),
            session_type: SessionType::Custom("Thread".to_string()),
            session_name: None,
        });
    }

    for key in [
        "sessionId",
        "agent_session_id",
        "agentSessionId",
        "conversationId",
    ] {
        if let Some(session_id) = json.get(key).and_then(|v| v.as_str()) {
            out.push(ExtractedSession {
                session_id: session_id.to_string(),
                session_type: SessionType::Custom("AgentSession".to_string()),
                session_name: None,
            });
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
                out.push(ExtractedSession {
                    session_id: session_id.to_string(),
                    session_type: SessionType::Custom("AgentSession".to_string()),
                    session_name: None,
                });
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
            out.push(ExtractedSession {
                session_id: run_id.to_string(),
                session_type: SessionType::Custom("RunMarker".to_string()),
                session_name: Some(format!("copilot-run:{run_id}")),
            });
        }
        idx = start.saturating_add(end);
        if idx >= body.len() {
            break;
        }
    }
}

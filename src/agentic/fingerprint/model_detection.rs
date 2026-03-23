use super::{AgentFramework, LlmProvider, RequestInfo};

pub(super) fn detect_framework(request: &RequestInfo) -> AgentFramework {
    if looks_like_copilot(request) {
        return AgentFramework::CopilotCli;
    }

    if let Some(process) = &request.process_name {
        let process_lower = process.to_lowercase();

        if process_lower.contains("claude") {
            return AgentFramework::ClaudeCode;
        }
        if process_lower == "gh" || process_lower.contains("copilot") {
            return AgentFramework::CopilotCli;
        }
        if process_lower.contains("cursor") {
            return AgentFramework::Cursor;
        }
        if process_lower.contains("windsurf") {
            return AgentFramework::Windsurf;
        }
        if process_lower.contains("aider") {
            return AgentFramework::Aider;
        }
    }

    if let Some(ua) = &request.user_agent {
        let ua_lower = ua.to_lowercase();

        if ua_lower.contains("openai-python") {
            return AgentFramework::OpenAIPython;
        }
        if ua_lower.contains("openai-node") || ua_lower.contains("openai/") {
            return AgentFramework::OpenAINode;
        }
        if ua_lower.contains("anthropic-python") || ua_lower.contains("claude-") {
            return AgentFramework::AnthropicPython;
        }
        if ua_lower.contains("anthropic-typescript") || ua_lower.contains("@anthropic-ai") {
            return AgentFramework::AnthropicNode;
        }
        if ua_lower.contains("langchain") {
            return AgentFramework::LangChain;
        }
        if ua_lower.contains("llamaindex") || ua_lower.contains("llama-index") {
            return AgentFramework::LlamaIndex;
        }
    }

    for key in request.headers.keys() {
        let key_lower = key.to_lowercase();
        if key_lower.contains("langchain") || key_lower == "x-langchain-request" {
            return AgentFramework::LangChain;
        }
        if key_lower.contains("llamaindex") {
            return AgentFramework::LlamaIndex;
        }
    }

    if let Some(body) = &request.body {
        let body_lower = body.to_lowercase();
        if body_lower.contains("crewai") || body_lower.contains("crew_agent") {
            return AgentFramework::CrewAI;
        }
        if body_lower.contains("autogen") || body_lower.contains("assistant_agent") {
            return AgentFramework::AutoGen;
        }
        if body_lower.contains("langchain") || body_lower.contains("lcel") {
            return AgentFramework::LangChain;
        }
    }

    match LlmProvider::from_hostname(&request.hostname) {
        LlmProvider::OpenAI | LlmProvider::Azure => AgentFramework::OpenAIPython,
        LlmProvider::Anthropic => AgentFramework::AnthropicPython,
        _ => AgentFramework::Unknown("Unknown".to_string()),
    }
}

pub(super) fn looks_like_copilot(request: &RequestInfo) -> bool {
    if let Some(process) = &request.process_name {
        let process_lower = process.to_ascii_lowercase();
        if process_lower.contains("copilot") {
            return true;
        }
    }

    if let Some(exe_path) = &request.exe_path {
        let exe_lower = exe_path.to_ascii_lowercase();
        if exe_lower.contains("copilot") {
            return true;
        }
    }

    if let Some(ua) = &request.user_agent {
        let ua_lower = ua.to_ascii_lowercase();
        if ua_lower.contains("copilot") || ua_lower.contains("github-copilot") {
            return true;
        }
    }

    let Some(pid) = request.pid else {
        return false;
    };

    let process_name = request
        .process_name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !(process_name.contains("mainthread")
        || process_name.contains("node")
        || process_name.is_empty())
    {
        return false;
    }

    let exe_link = format!("/proc/{pid}/exe");
    let Ok(exe_path) = std::fs::read_link(exe_link) else {
        return false;
    };
    let exe_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if exe_name == "copilot"
        || exe_path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("copilot")
    {
        return true;
    }

    let cmdline_path = format!("/proc/{pid}/cmdline");
    let Ok(cmdline_bytes) = std::fs::read(cmdline_path) else {
        return false;
    };
    cmdline_bytes
        .split(|b| *b == 0)
        .filter_map(|part| std::str::from_utf8(part).ok())
        .any(|arg| arg.to_ascii_lowercase().contains("copilot"))
}

pub(super) fn extract_model(body: &Option<String>) -> Option<String> {
    if let Some(body) = body {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(model) = json.get("model").and_then(|v| v.as_str()) {
                return Some(model.to_string());
            }
        }

        if let Some(start) = body.find("\"model\":") {
            let rest = &body[start + 8..];
            if let Some(quote_start) = rest.find('"') {
                let rest = &rest[quote_start + 1..];
                if let Some(quote_end) = rest.find('"') {
                    return Some(rest[..quote_end].to_string());
                }
            }
        }
    }
    None
}

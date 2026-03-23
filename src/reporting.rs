//! Reporting helpers for generating branded daily HTML reports.

use anyhow::Result;
use std::fs::{create_dir_all, read_to_string, write};
use std::path::PathBuf;

const DAILY_REPORT_TEMPLATE: &str = include_str!("reporting/templates/daily_report.html");

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render_daily_report_html(
    report: &serde_json::Value,
    source_path: &str,
    company: &str,
) -> Result<String> {
    let report_json = serde_json::to_string_pretty(report)?.replace("</", "<\\/");
    let generated_at = report
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let company_escaped = html_escape(company);
    let source_escaped = html_escape(source_path);
    let html = DAILY_REPORT_TEMPLATE
        .replace("{{COMPANY}}", &company_escaped)
        .replace("{{GENERATED_AT}}", &html_escape(generated_at))
        .replace("{{SOURCE_PATH}}", &source_escaped)
        .replace("{{REPORT_JSON}}", &report_json);
    Ok(html)
}

pub fn generate_daily_report_html(
    input_path: &str,
    output_path: Option<&str>,
    company: &str,
) -> Result<PathBuf> {
    let raw = read_to_string(input_path)?;
    let report: serde_json::Value = serde_json::from_str(&raw)?;
    let report_type = report
        .get("report_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if report_type != "security_summary" {
        anyhow::bail!(
            "expected report_type=security_summary in input JSON, found '{}'",
            report_type
        );
    }

    let html = render_daily_report_html(&report, input_path, company)?;
    let out_path = if let Some(path) = output_path {
        PathBuf::from(path)
    } else {
        let mut p = PathBuf::from(input_path);
        p.set_extension("html");
        p
    };
    if let Some(parent) = out_path.parent() {
        create_dir_all(parent)?;
    }
    write(&out_path, html)?;
    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_daily_report_html_contains_embedded_json_and_sections() {
        let report = serde_json::json!({
            "report_type": "security_summary",
            "generated_at": "2026-03-23T00:00:00Z",
            "summary": {
                "total_agents": 2,
                "total_llm_calls": 10,
                "total_tool_calls": 5,
                "total_cost_usd": 1.5,
                "total_alerts": 3,
                "total_blocks": 1
            },
            "alerts_by_type": { "prompt_injection": 1 },
            "secrets_detected": [],
            "pii_detected": [],
            "injection_attempts": [{
                "timestamp": "2026-03-23T00:01:00Z",
                "agent_id": "agent-1",
                "attack_type": "prompt_injection",
                "pattern": "ignore previous instructions",
                "risk_score": 92,
                "action": "blocked"
            }],
            "dangerous_tool_calls": [],
            "recommendations": ["Review risky prompts."]
        });

        let html =
            render_daily_report_html(&report, "examples/sample-report-daily.json", "Seconize")
                .expect("report html should render");
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("daily-report-json"));
        assert!(html.contains("alerts-table-body"));
        assert!(html.contains("security_summary"));
    }
}

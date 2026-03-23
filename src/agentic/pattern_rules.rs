use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use std::sync::OnceLock;

static EXTERNAL_PATTERN_RULES: OnceLock<ExternalPatternRules> = OnceLock::new();

#[derive(Debug, Clone, Default)]
pub struct ExternalPatternRules {
    pub pii_patterns: Vec<ExternalPiiPattern>,
    pub prompt_injection_patterns: Vec<String>,
    pub prompt_jailbreak_patterns: Vec<String>,
    pub prompt_extraction_patterns: Vec<String>,
    pub prompt_sensitive_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExternalPiiPattern {
    pub pii_type: String,
    pub regex: String,
    pub severity: String,
    pub redact_format: String,
}

#[derive(Debug, Deserialize, Default)]
struct ExternalPatternRulesFile {
    pii: Option<ExternalPiiSection>,
    prompt: Option<ExternalPromptSection>,
}

#[derive(Debug, Deserialize, Default)]
struct ExternalPiiSection {
    patterns: Vec<ExternalPiiPatternToml>,
}

#[derive(Debug, Deserialize)]
struct ExternalPiiPatternToml {
    pii_type: String,
    regex: String,
    severity: String,
    redact_format: String,
}

#[derive(Debug, Deserialize, Default)]
struct ExternalPromptSection {
    injection_patterns: Option<Vec<String>>,
    jailbreak_patterns: Option<Vec<String>>,
    extraction_patterns: Option<Vec<String>>,
    sensitive_patterns: Option<Vec<String>>,
}

pub fn load_external_pattern_rules(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading external rules file: {}", path.display()))?;
    let parsed: ExternalPatternRulesFile = toml::from_str(&content).with_context(|| {
        format!(
            "failed parsing external rules file TOML: {}",
            path.display()
        )
    })?;

    let mut rules = ExternalPatternRules::default();

    if let Some(pii) = parsed.pii {
        for entry in pii.patterns {
            validate_pii_pattern(&entry)?;
            rules.pii_patterns.push(ExternalPiiPattern {
                pii_type: entry.pii_type,
                regex: entry.regex,
                severity: entry.severity,
                redact_format: entry.redact_format,
            });
        }
    }

    if let Some(prompt) = parsed.prompt {
        rules.prompt_injection_patterns = validate_regex_list(
            prompt.injection_patterns.unwrap_or_default(),
            "prompt.injection_patterns",
        )?;
        rules.prompt_jailbreak_patterns = validate_regex_list(
            prompt.jailbreak_patterns.unwrap_or_default(),
            "prompt.jailbreak_patterns",
        )?;
        rules.prompt_extraction_patterns = validate_regex_list(
            prompt.extraction_patterns.unwrap_or_default(),
            "prompt.extraction_patterns",
        )?;
        rules.prompt_sensitive_patterns = validate_regex_list(
            prompt.sensitive_patterns.unwrap_or_default(),
            "prompt.sensitive_patterns",
        )?;
    }

    EXTERNAL_PATTERN_RULES
        .set(rules)
        .map_err(|_| anyhow::anyhow!("external pattern rules were already initialized"))?;
    Ok(())
}

pub fn external_pattern_rules() -> Option<&'static ExternalPatternRules> {
    EXTERNAL_PATTERN_RULES.get()
}

fn validate_pii_pattern(entry: &ExternalPiiPatternToml) -> Result<()> {
    if entry.pii_type.trim().is_empty() {
        return Err(anyhow::anyhow!("pii pattern pii_type cannot be empty"));
    }
    if entry.redact_format.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "pii pattern redact_format cannot be empty for {}",
            entry.pii_type
        ));
    }
    match entry.severity.as_str() {
        "low" | "medium" | "high" | "critical" => {},
        _ => {
            return Err(anyhow::anyhow!(
                "pii pattern severity must be one of low|medium|high|critical for {}",
                entry.pii_type
            ));
        },
    }
    regex::Regex::new(&entry.regex).with_context(|| {
        format!(
            "invalid pii regex for type {}: {}",
            entry.pii_type, entry.regex
        )
    })?;
    Ok(())
}

fn validate_regex_list(list: Vec<String>, field_name: &str) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(list.len());
    for pattern in list {
        regex::Regex::new(&pattern)
            .with_context(|| format!("invalid regex in {field_name}: {pattern}"))?;
        out.push(pattern);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_regex_list_rejects_invalid_regex() {
        let res = validate_regex_list(vec!["(".to_string()], "prompt.injection_patterns");
        assert!(res.is_err());
    }

    #[test]
    fn test_validate_pii_pattern_rejects_unknown_severity() {
        let entry = ExternalPiiPatternToml {
            pii_type: "employee_id".to_string(),
            regex: r"\bEMP-[0-9]{6}\b".to_string(),
            severity: "urgent".to_string(),
            redact_format: "[EMP_ID]".to_string(),
        };
        let res = validate_pii_pattern(&entry);
        assert!(res.is_err());
    }
}

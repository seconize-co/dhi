use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use std::sync::OnceLock;

static EXTERNAL_PATTERN_RULES: OnceLock<ExternalPatternRules> = OnceLock::new();
const MAX_PATTERNS_PER_SECTION: usize = 256;
const MAX_REGEX_LENGTH: usize = 512;
const MAX_PII_TYPE_LENGTH: usize = 64;
const MAX_REDACT_FORMAT_LENGTH: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalPatternRules {
    pub pii_patterns: Vec<ExternalPiiPattern>,
    pub prompt_injection_patterns: Vec<String>,
    pub prompt_jailbreak_patterns: Vec<String>,
    pub prompt_extraction_patterns: Vec<String>,
    pub prompt_sensitive_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    let rules = parse_external_pattern_rules_content(&content).with_context(|| {
        format!(
            "failed parsing external rules file TOML: {}",
            path.display()
        )
    })?;

    if let Some(existing) = EXTERNAL_PATTERN_RULES.get() {
        if existing == &rules {
            return Ok(());
        }
        return Err(anyhow::anyhow!(
            "external pattern rules were already initialized with a different configuration"
        ));
    }

    EXTERNAL_PATTERN_RULES
        .set(rules)
        .map_err(|_| anyhow::anyhow!("external pattern rules were already initialized"))?;
    Ok(())
}

fn parse_external_pattern_rules_content(content: &str) -> Result<ExternalPatternRules> {
    let parsed: ExternalPatternRulesFile = toml::from_str(content)?;
    let mut rules = ExternalPatternRules::default();

    if let Some(pii) = parsed.pii {
        enforce_section_limit(pii.patterns.len(), "pii.patterns")?;
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

    Ok(rules)
}

pub fn external_pattern_rules() -> Option<&'static ExternalPatternRules> {
    EXTERNAL_PATTERN_RULES.get()
}

fn validate_pii_pattern(entry: &ExternalPiiPatternToml) -> Result<()> {
    if entry.pii_type.trim().is_empty() {
        return Err(anyhow::anyhow!("pii pattern pii_type cannot be empty"));
    }
    if entry.pii_type.len() > MAX_PII_TYPE_LENGTH {
        return Err(anyhow::anyhow!(
            "pii pattern pii_type exceeds {} characters",
            MAX_PII_TYPE_LENGTH
        ));
    }
    if entry.redact_format.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "pii pattern redact_format cannot be empty for {}",
            entry.pii_type
        ));
    }
    if entry.redact_format.len() > MAX_REDACT_FORMAT_LENGTH {
        return Err(anyhow::anyhow!(
            "pii pattern redact_format exceeds {} characters for {}",
            MAX_REDACT_FORMAT_LENGTH,
            entry.pii_type
        ));
    }
    if entry.regex.len() > MAX_REGEX_LENGTH {
        return Err(anyhow::anyhow!(
            "pii regex exceeds {} characters for {}",
            MAX_REGEX_LENGTH,
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
    enforce_section_limit(list.len(), field_name)?;
    let mut out = Vec::with_capacity(list.len());
    for pattern in list {
        if pattern.len() > MAX_REGEX_LENGTH {
            return Err(anyhow::anyhow!(
                "{field_name} contains a regex exceeding {MAX_REGEX_LENGTH} characters"
            ));
        }
        regex::Regex::new(&pattern)
            .with_context(|| format!("invalid regex in {field_name}: {pattern}"))?;
        out.push(pattern);
    }
    Ok(out)
}

fn enforce_section_limit(count: usize, section: &str) -> Result<()> {
    if count > MAX_PATTERNS_PER_SECTION {
        return Err(anyhow::anyhow!(
            "{section} exceeds max entries ({MAX_PATTERNS_PER_SECTION})"
        ));
    }
    Ok(())
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

    #[test]
    fn test_parse_external_pattern_rules_content_valid() {
        let content = r#"
[pii]
patterns = [
  { pii_type = "employee_id", regex = "\\bEMP-[0-9]{6}\\b", severity = "medium", redact_format = "[EMP_ID]" },
]

[prompt]
injection_patterns = ['(?i)ignore\\s+company\\s+policy']
jailbreak_patterns = ['(?i)simulate\\s+an\\s+unrestricted\\s+assistant']
extraction_patterns = ['(?i)dump\\s+hidden\\s+instructions']
sensitive_patterns = ['(?i)internal[_-]?token\\s*[=:]\\s*[A-Za-z0-9_-]{16,}']
"#;
        let parsed =
            parse_external_pattern_rules_content(content).expect("valid parse should pass");
        assert_eq!(parsed.pii_patterns.len(), 1);
        assert_eq!(parsed.prompt_injection_patterns.len(), 1);
        assert_eq!(parsed.prompt_jailbreak_patterns.len(), 1);
        assert_eq!(parsed.prompt_extraction_patterns.len(), 1);
        assert_eq!(parsed.prompt_sensitive_patterns.len(), 1);
    }

    #[test]
    fn test_parse_external_pattern_rules_rejects_invalid_prompt_regex() {
        let content = r#"
[prompt]
injection_patterns = ['(']
"#;
        let res = parse_external_pattern_rules_content(content);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_external_pattern_rules_rejects_empty_pii_type() {
        let content = r#"
[pii]
patterns = [
  { pii_type = " ", regex = "\\bEMP-[0-9]{6}\\b", severity = "medium", redact_format = "[EMP_ID]" },
]
"#;
        let res = parse_external_pattern_rules_content(content);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_external_pattern_rules_rejects_oversized_section() {
        let mut patterns = String::new();
        for i in 0..=MAX_PATTERNS_PER_SECTION {
            patterns.push_str(&format!("'(?i)test{i}',"));
        }
        let content = format!("[prompt]\ninjection_patterns = [{patterns}]");
        let res = parse_external_pattern_rules_content(&content);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_external_pattern_rules_missing_file_fails_with_context() {
        let path = Path::new("/tmp/dhi-nonexistent-pattern-rules.toml");
        let res = load_external_pattern_rules(path);
        assert!(res.is_err());
        let err = res.expect_err("expected missing file error");
        assert!(err
            .to_string()
            .contains("failed reading external rules file"));
    }
}

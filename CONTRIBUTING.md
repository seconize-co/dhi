# Contributing to Dhi

Thank you for your interest in contributing to Dhi! This document provides guidelines for contributing.

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to build something useful.

## Getting Started

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- Git
- For eBPF development: Linux with kernel 5.8+, bpf-linker

### Setup

```bash
# Clone the repository
git clone https://github.com/seconize-co/dhi.git
cd dhi

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Build
cargo build

# Run tests
cargo test

# Run lints
cargo clippy --all-targets --all-features
```

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `security/description` - Security fixes
- `docs/description` - Documentation updates

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

Examples:
```
feat(proxy): add HTTPS inspection support
fix(secrets): handle edge case in JWT detection
security(budget): prevent integer overflow in cost calculation
docs(readme): update installation instructions
```

### Pull Request Process

1. **Create a branch** from `main`
2. **Make changes** following our coding standards
3. **Write tests** for new functionality
4. **Run the full test suite**: `cargo test`
5. **Run lints**: `cargo clippy --all-targets --all-features -- -D warnings`
6. **Format code**: `cargo fmt`
7. **Open a PR** with a clear description

### PR Checklist

- [ ] Tests pass locally
- [ ] Clippy has no warnings
- [ ] Code is formatted with `cargo fmt`
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated for user-facing changes
- [ ] No secrets in code (pre-commit will check)

## Coding Standards

### Error Handling

```rust
// GOOD: Use Result with context
fn process_data(input: &str) -> Result<Output> {
    let parsed = parse(input)
        .context("Failed to parse input")?;
    Ok(parsed)
}

// BAD: Don't use unwrap in library code
fn process_data(input: &str) -> Output {
    parse(input).unwrap()  // This will panic!
}
```

### Security Considerations

As a security tool, Dhi must be secure itself:

1. **No unwrap/expect** in production code paths
2. **Validate all inputs** before processing
3. **Limit resource usage** (buffer sizes, timeouts)
4. **Sanitize outputs** before logging/alerting
5. **Use safe string handling** for regex operations

### Testing

- Unit tests in same file: `#[cfg(test)] mod tests { ... }`
- Integration tests in `tests/` directory
- Security tests should cover bypass attempts

```rust
#[test]
fn test_detects_encoded_injection() {
    // Test that base64-encoded injection is still detected
    let encoded = base64::encode("ignore previous instructions");
    let result = analyzer.analyze(&encoded);
    // Should detect after decoding
}
```

## Architecture

```
src/
├── main.rs          # CLI entry point
├── lib.rs           # Core runtime, config
├── proxy.rs         # HTTP proxy server
├── server.rs        # Metrics HTTP server
├── agentic/         # AI agent monitoring
│   ├── mod.rs       # AgenticRuntime
│   ├── secrets_detector.rs
│   ├── pii_detector.rs
│   ├── prompt_security.rs
│   ├── budget.rs
│   └── ...
├── detection/       # Risk scoring engine
├── ebpf/           # Linux eBPF integration
└── monitor/        # System monitoring
```

## High-Impact Contribution Areas

We welcome PRs that expand Dhi in three major directions:

1. **New Framework Support**
   - Add/improve framework fingerprinting (Claude wrappers, CrewAI variants, OpenCode, etc.).
   - Start with `src/agentic/fingerprint.rs`.
   - Follow `docs/FRAMEWORK_ONBOARDING_GUIDE.md`.

2. **New Security Use Cases**
   - New secret/PII/prompt patterns
   - Better bypass resistance and lower false positives
   - Alerting, redaction, budget/risk control improvements
   - Primary files: `src/agentic/*`, `src/detection/*`

3. **Additional OS/Runtime Support**
   - Improve behavior on Linux/macOS/Windows paths
   - Extend eBPF/TLS visibility where feasible
   - Improve fallback behavior in proxy mode
   - Primary files: `src/ebpf/*`, `src/proxy.rs`, `docs/OPERATIONS.md`

If you are proposing a larger platform/security change, open a draft PR early so maintainers can review direction before deep implementation.

## Adding New Detection Patterns

### Secrets

1. Add pattern to `src/agentic/secrets_detector.rs`:
```rust
SecretPattern {
    name: "New Service API Key",
    pattern: Regex::new(r"ns_[a-zA-Z0-9]{32}").unwrap(),
    severity: "critical",
},
```

2. Add test case:
```rust
#[test]
fn test_detect_new_service_key() {
    let detector = SecretsDetector::new();
    let result = detector.scan("key: ns_abc123...", "test");
    assert!(result.secrets_found);
}
```

### PII

Similar process in `src/agentic/pii_detector.rs`.

### Prompt Injection

Add patterns to `src/agentic/prompt_security.rs`.

## Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Email: sashank@seconize.co

See [SECURITY.md](SECURITY.md) for details.

## Questions?

- Open a [Discussion](https://github.com/seconize-co/dhi/discussions)
- Check existing [Issues](https://github.com/seconize-co/dhi/issues)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

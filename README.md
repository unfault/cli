# Unfault CLI

**A calm reviewer for thoughtful engineers.**

Unfault analyzes your code for clarity, boundaries, and behavior—highlighting places where decisions matter, before reality does. You write the code. Unfault helps you build it right.

[![Crates.io](https://img.shields.io/crates/v/unfault)](https://crates.io/crates/unfault)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Why Unfault?

Production issues don't announce themselves. That missing timeout? The unhandled edge case? The retry logic that isn't there? They surface at 3 AM, pages deep into an incident.

Unfault catches these patterns early—during development, not during outages. It's a linter for production-readiness, focused on:

- **Stability** — HTTP timeouts, circuit breakers, retry patterns
- **Correctness** — Error handling, boundary conditions, type safety
- **Performance** — N+1 queries, missing indexes, blocking calls
- **Scalability** — Resource limits, connection pooling, caching patterns

## Quick Start

```bash
# Install
cargo install unfault

# Authenticate
unfault login

# Analyze your code
unfault review
```

That's it. Unfault scans your codebase, detects frameworks and languages, and reports findings in seconds.

## Installation

### From Releases (Recommended)

Download the latest binary from [Releases](https://github.com/unfault/cli/releases) and add it to your PATH.

### From crates.io

```bash
cargo install unfault
```

### From Source

```bash
git clone https://github.com/unfault/cli
cd cli
cargo build --release
```

## Commands

### `unfault login`

Authenticate using secure device flow—no API keys in your terminal history.

```bash
unfault login
# Visit https://app.unfault.dev/authorize and enter the displayed code
```

### `unfault review`

Analyze your codebase for production-readiness issues.

```bash
# Basic output (grouped by severity)
unfault review

# Full details with suggested fixes
unfault review --output full

# JSON for integration with other tools
unfault review --output json

# Focus on specific dimensions
unfault review --dimension stability --dimension performance
```

**Output Modes:**

| Mode | Description |
|------|-------------|
| `basic` | Grouped by severity, rule counts (default) |
| `concise` | Summary statistics only |
| `full` | Detailed findings with diffs |
| `json` | Machine-readable output |

### `unfault ask`

Query your project's health using natural language (requires prior `review` sessions).

```bash
# Ask about your codebase
unfault ask "What are my main stability concerns?"

# Scope to a specific workspace
unfault ask "Show recent issues" --workspace wks_abc123

# Get raw context without AI synthesis
unfault ask "Performance problems" --no-llm
```

Configure an LLM for AI-powered answers:

```bash
# OpenAI
unfault config llm openai --model gpt-4

# Anthropic
unfault config llm anthropic --model claude-3-5-sonnet-latest

# Local Ollama
unfault config llm ollama --model llama3.2
```

### `unfault status`

Check authentication and connectivity.

```bash
unfault status
```

### `unfault config`

Manage CLI configuration.

```bash
# Show current config
unfault config show

# Configure LLM provider
unfault config llm openai --model gpt-4o

# View LLM settings
unfault config llm show

# Remove LLM configuration
unfault config llm remove
```

## CI/CD Integration

Unfault is designed for CI pipelines. Use exit codes to gate deployments:

```yaml
# GitHub Actions
- name: Production Readiness Check
  run: unfault review
  continue-on-error: false
```

```yaml
# GitLab CI
production_check:
  script:
    - unfault review --output json > unfault-report.json
  artifacts:
    reports:
      codequality: unfault-report.json
  allow_failure: false
```

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Success, no issues | ✅ Proceed |
| `1` | General error | 🔍 Check logs |
| `2` | Configuration error | Run `unfault login` |
| `3` | Authentication failed | Re-authenticate |
| `4` | Network error | Check connectivity |
| `5` | **Findings detected** | 🚨 Review issues |
| `6` | Invalid input | Check arguments |
| `7` | Service unavailable | Retry later |
| `8` | Session error | Retry analysis |
| `10` | Subscription required | Upgrade plan |

**CI Example: Fail on findings**

```bash
unfault review
if [ $? -eq 5 ]; then
  echo "Production readiness issues found. Blocking deployment."
  exit 1
fi
```

## Supported Languages & Frameworks

| Language | Frameworks |
|----------|------------|
| Python | FastAPI, Flask, Django, httpx, requests |
| Go | net/http, gin, echo |
| Rust | reqwest, hyper, actix-web |
| TypeScript | Express, fetch, axios |

Unfault automatically detects your stack and applies relevant rules.

## Configuration

Configuration is stored in `~/.config/unfault/config.json`:

```json
{
  "api_key": "uf_live_...",
  "base_url": "https://api.unfault.dev",
  "llm": {
    "provider": "openai",
    "model": "gpt-4",
    "api_key": "sk-..."
  }
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `UNFAULT_BASE_URL` | Override API endpoint |
| `OPENAI_API_KEY` | OpenAI API key (for `ask` command) |
| `ANTHROPIC_API_KEY` | Anthropic API key (for `ask` command) |

## What Unfault Finds

### Stability Issues

```python
# ❌ Missing timeout
response = httpx.get("https://api.example.com/data")

# ✅ Suggested fix
response = httpx.get("https://api.example.com/data", timeout=30.0)
```

### Error Handling Gaps

```go
// ❌ Ignored error
result, _ := riskyOperation()

// ✅ Suggested fix
result, err := riskyOperation()
if err != nil {
    return fmt.Errorf("risky operation failed: %w", err)
}
```

### Performance Concerns

```python
# ❌ N+1 query pattern
for user in users:
    orders = db.query(Order).filter(Order.user_id == user.id).all()

# ✅ Suggested fix
orders = db.query(Order).filter(Order.user_id.in_([u.id for u in users])).all()
```

## Philosophy

Unfault is opinionated but not dogmatic. It focuses on patterns that matter in production:

- **Fast feedback** — Analysis completes in seconds, not minutes
- **Actionable fixes** — Every finding includes a suggested patch
- **Low noise** — Rules are tuned to minimize false positives
- **Developer-first** — Designed for the terminal, not dashboards

## Troubleshooting

### "Not logged in"

```bash
unfault login
```

### "No source files found"

Ensure you're running `unfault review` from a directory containing supported source files (`.py`, `.go`, `.rs`, `.ts`, `.js`).

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Run tests
cargo test

# Build release
cargo build --release
```

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Write with joy. Ship with clarity.</strong><br>
  <a href="https://unfault.dev">unfault.dev</a>
</p>
# Unfault CLI

**A cognitive context engine for thoughtful engineers.**

Unfault helps you understand what your code *means* and *does* — while you're writing it. It reveals the runtime impact of your changes, showing you which routes use a function, what safeguards are (or aren't) in place, and how your code fits into the bigger picture.

[![Crates.io](https://img.shields.io/crates/v/unfault)](https://crates.io/crates/unfault)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Why Unfault?

Software complexity grows invisibly. That function you just changed? It might be called by five different API routes. That missing timeout? It's three layers deep in a request path with no retry logic.

Unfault illuminates these connections. It builds a semantic graph of your codebase and gives you instant answers to questions like:

- **"Where is this function used?"** — See which routes, handlers, and background jobs depend on it
- **"What safeguards exist in this path?"** — Know if there's structured logging, retries, or error boundaries
- **"What's the impact of changing this?"** — Understand the blast radius before you commit

This isn't about warnings or alerts. It's about **cognitive support** — keeping the runtime context visible so you can stay in flow while making informed decisions.

## Quick Start

```bash
# Install
cargo install unfault

# Authenticate
unfault login

# Understand your codebase
unfault review
```

## Copy/Paste Oneliners

Real scenarios, ready to run. Just paste and go.

### Before You Commit

```bash
# Review only what you changed — fast, focused feedback
unfault review --uncommitted

# Same thing, JSON for your editor/script
unfault review --uncommitted --output json
```

### For Coding Agents (Cursor, Copilot, Claude)

```bash
# LLM-optimized output — paste this into your agent's context
unfault review --llm

# Focus on your changes, formatted for agents
unfault review --uncommitted --llm

# Review specific files with full workspace context
unfault review --llm --file src/api/routes.py --file src/api/handlers.py
```

### CI/CD Integration

```bash
# SARIF for GitHub Code Scanning
unfault review --output sarif > results.sarif

# Fail the build if issues found (exit code 5)
unfault review --output json && echo "Clean!" || echo "Issues found"

# Skip test files in CI
unfault review --output sarif  # (tests excluded by default)
```

### Deep Dives

```bash
# Full detailed output with fix suggestions
unfault review --output full

# Focus on stability issues only
unfault review --dimension stability --output full

# Include test files in analysis
unfault review --include-tests --output full

# See what would be fixed (dry run)
unfault review --dry-run
```

### Impact Analysis

```bash
# What breaks if I change this file?
unfault graph impact src/core/auth.py

# Find the most critical files in your codebase
unfault graph critical --limit 10

# What depends on this library?
unfault graph library requests
```

### Ask Your Codebase

```bash
# Quick semantic search
unfault ask "functions without error handling"

# With LLM-powered explanations
unfault ask "what happens if the database is down?" --llm
```

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

Authenticate using secure device flow — no API keys in your terminal history.

```bash
unfault login
# Visit https://app.unfault.dev/authorize and enter the displayed code
```

### `unfault review`

Analyze your codebase and surface behavioral insights.

```bash
# Standard analysis (grouped by dimension)
unfault review

# Detailed insights with context
unfault review --output full

# JSON for integration with other tools
unfault review --output json

# Focus on specific dimensions
unfault review --dimension stability --dimension performance

# Review only uncommitted changes (git required)
unfault review --uncommitted

# Review specific files (with full workspace context)
unfault review --file src/api.py --file src/utils.py

# LLM-optimized JSON for coding agents
unfault review --llm

# Combine: uncommitted files, formatted for agents
unfault review --uncommitted --llm --top 20
```

**Output Modes:**

| Mode | Description |
|------|-------------|
| `basic` | Grouped by dimension, insight counts (default) |
| `concise` | Summary statistics only |
| `full` | Detailed insights with suggestions |
| `json` | Machine-readable output |
| `sarif` | SARIF 2.1.0 for IDE integration |
| `llm` | Compact JSON optimized for LLM coding agents |

**Filtering Options:**

| Flag | Description |
|------|-------------|
| `--uncommitted` | Only show findings for uncommitted files (staged, unstaged, untracked) |
| `--file PATH` | Only show findings for specific files (repeatable) |
| `--top N` | Limit findings in LLM output (default: 50, max: 200) |
| `--include-tests` | Include test files in analysis (excluded by default) |

### `unfault ask`

Query your codebase using natural language.

```bash
# Ask about your codebase
unfault ask "What functions lack structured logging?"

# Scope to a specific workspace
unfault ask "Show me the critical paths" --workspace wks_abc123

# Use the configured LLM for a longer answer
unfault ask "Which routes have no retry logic?" --llm
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

### `unfault graph`

Query the code graph for impact analysis, dependencies, and relationships.

```bash
# Build/refresh the code graph
unfault graph refresh

# What's affected if I change this file?
unfault graph impact auth/middleware.py

# Find files that use a specific library
unfault graph library requests

# Find external dependencies of a file
unfault graph deps main.py

# Find the most connected files in the codebase
unfault graph critical --limit 10

# Get graph statistics
unfault graph stats
```

**Understanding the Graph:**

The code graph captures semantic relationships — imports, function calls, route handlers, middleware chains. When you ask "what's affected?", you're not just looking at file imports; you're seeing the full call graph that traces how a change propagates through your system.

### `unfault lsp`

Start the Language Server Protocol server for IDE integration.

```bash
# Start LSP server (used by VS Code extension)
unfault lsp

# With verbose logging for debugging
unfault lsp --verbose
```

The LSP server provides:
- **Real-time insights** as you type
- **Hover information** showing function impact and context
- **Quick fixes** with contextual suggestions

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

## IDE Integration

The primary way to use Unfault is through your IDE. The VS Code extension connects to the CLI's LSP server, providing:

- **Inline context** — Hover over a function to see where it's used and what safeguards exist
- **File importance** — Status bar shows how central a file is to your codebase
- **Dependency awareness** — Know which files will be affected by your changes

Install the extension: [Unfault for VS Code](https://marketplace.visualstudio.com/items?itemName=unfault.unfault-vscode)

## CI/CD Integration

While Unfault shines in the IDE, it's also valuable in CI pipelines for tracking codebase health:

```yaml
# GitHub Actions
- name: Analyze Codebase
  run: unfault review --output sarif > results.sarif

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Success | ✅ Proceed |
| `1` | General error | 🔍 Check logs |
| `2` | Configuration error | Run `unfault login` |
| `3` | Authentication failed | Re-authenticate |
| `4` | Network error | Check connectivity |
| `5` | **Insights detected** | 📊 Review insights |
| `6` | Invalid input | Check arguments |
| `7` | Service unavailable | Retry later |
| `8` | Session error | Retry analysis |
| `10` | Subscription required | Upgrade plan |

## Supported Languages & Frameworks

| Language | Frameworks |
|----------|------------|
| Python | FastAPI, Flask, Django, httpx, requests |
| Go | net/http, gin, echo |
| Rust | reqwest, hyper, actix-web |
| TypeScript | Express, fetch, axios |

Unfault automatically detects your stack and builds the appropriate semantic graph.

## Configuration

Configuration is stored in `~/.config/unfault/config.json`:

```json
{
  "api_key": "sk_live_...",
  "base_url": "https://app.unfault.dev",
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

## What Unfault Reveals

### Missing Safeguards

```python
# Unfault shows: "This function has no timeout.
# Called by: /api/users endpoint, /api/orders endpoint
# No retry logic in call chain."
response = httpx.get("https://api.example.com/data")
```

### Error Handling Context

```go
// Unfault shows: "Unchecked error.
// This function is called by: ProcessOrder handler
// Call chain has no structured logging."
result, _ := riskyOperation()
```

### Query Patterns

```python
# Unfault shows: "N+1 query pattern detected.
# This loop is inside: get_user_dashboard route
# 47 users in average request = 47 extra queries"
for user in users:
    orders = db.query(Order).filter(Order.user_id == user.id).all()
```

## Philosophy

Unfault is designed around three principles:

1. **Context, not warnings** — Information appears when you need it, not as a wall of alerts
2. **Flow preservation** — Insights are quiet and inline; they don't interrupt your work
3. **Runtime awareness** — Understand how your code behaves, not just how it's structured

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
  <strong>Understand your code. Stay in flow.</strong><br>
  <a href="https://unfault.dev">unfault.dev</a>
</p>

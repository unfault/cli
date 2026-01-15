# Unfault CLI

**A calm reviewer for thoughtful engineers.**

Unfault helps you understand what your code *means* and *does* while you’re writing it.
It builds a semantic graph of your codebase and surfaces production-readiness findings (timeouts, retries, error handling, risky patterns) with actionable context.

[![Crates.io](https://img.shields.io/crates/v/unfault)](https://crates.io/crates/unfault)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> The documentation is the source of truth.
> This README stays intentionally short and points you to the right guides.

---

## Install

```bash
cargo install unfault
```

Or download a prebuilt binary from GitHub Releases:
https://github.com/unfault/cli/releases

## Authenticate

```bash
unfault login
unfault status
```

## Quick Start

```bash
# Run from your project root
unfault review
```

## Copy/Paste Oneliners

A few small habits that keep you in flow.

```bash
# Before you commit: review only what changed
unfault review --uncommitted

# If you want the full story (same scope)
unfault review --uncommitted --output full

# For coding agents: compact, actionable JSON
unfault review --uncommitted --llm --top 20

# CI/CD: SARIF for GitHub Code Scanning
unfault review --output sarif > results.sarif

# Before a refactor: check blast radius
unfault graph impact path/to/file.py

# When you're not sure where to start
unfault ask "Which external calls lack timeouts?"
```

## Docs

- Docs home: https://unfault.dev/docs
- CLI guide: https://unfault.dev/docs/guides/cli/
- Copy/paste oneliners: https://unfault.dev/docs/guides/oneliners/
- Use with AI agents: https://unfault.dev/docs/guides/agents/
- CI/CD: https://unfault.dev/docs/guides/cicd/
- CLI reference: https://unfault.dev/docs/reference/cli/

## Contributing

```bash
cargo test
cargo clippy --all-features -- -D warnings
```

See `CONTRIBUTING.md` for details.

---

<p align="center">
  <strong>Understand your code. Stay in flow.</strong><br>
  <a href="https://unfault.dev">unfault.dev</a>
</p>

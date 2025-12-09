# Contributing to Unfault CLI

Thank you for your interest in contributing to Unfault! We welcome contributions from the community and are grateful for any help you can provide.

## Table of Contents

- [Contributing to Unfault CLI](#contributing-to-unfault-cli)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [Getting Started](#getting-started)
  - [Development Setup](#development-setup)
    - [Prerequisites](#prerequisites)
    - [Building](#building)
    - [Project Structure](#project-structure)
  - [Making Changes](#making-changes)
  - [Code Style](#code-style)
    - [Formatting](#formatting)
    - [Linting](#linting)
    - [Guidelines](#guidelines)
    - [Example Code Style](#example-code-style)
  - [Testing](#testing)
    - [Running Tests](#running-tests)
    - [Writing Tests](#writing-tests)
  - [Commit Messages](#commit-messages)
    - [Types](#types)
    - [Examples](#examples)
  - [Pull Request Process](#pull-request-process)
    - [PR Checklist](#pr-checklist)
  - [Reporting Bugs](#reporting-bugs)
    - [Example Bug Report](#example-bug-report)
  - [Suggesting Features](#suggesting-features)
  - [Questions?](#questions)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, constructive, and professional in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/cli.git
   cd cli
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/unfault/cli.git
   ```

## Development Setup

### Prerequisites

- **Rust 1.70+** — Install via [rustup](https://rustup.rs/)
- **Git** — For version control

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run the CLI directly
cargo run -- review
```

### Project Structure

```
src/
├── main.rs              # Entry point
├── lib.rs               # Library exports
├── config.rs            # Configuration management
├── errors.rs            # Error types
├── exit_codes.rs        # CLI exit codes
├── api/                 # API client modules
│   ├── auth.rs          # Authentication
│   ├── client.rs        # HTTP client
│   ├── llm.rs           # LLM integration
│   ├── rag.rs           # RAG queries
│   └── session.rs       # Session management
├── commands/            # CLI commands
│   ├── ask.rs           # `unfault ask`
│   ├── config.rs        # `unfault config`
│   ├── login.rs         # `unfault login`
│   ├── review.rs        # `unfault review`
│   └── status.rs        # `unfault status`
└── session/             # Session handling
    ├── file_collector.rs
    ├── runner.rs
    ├── workspace.rs
    └── workspace_id.rs
```

## Making Changes

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Keep your fork up to date**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

3. **Make your changes** following our code style guidelines

4. **Test your changes** thoroughly

5. **Commit your changes** with clear, descriptive messages

## Code Style

We follow standard Rust conventions with some project-specific guidelines:

### Formatting

```bash
# Format code before committing
cargo fmt

# Check formatting without changes
cargo fmt --check
```

### Linting

```bash
# Run clippy for lints
cargo clippy -- -D warnings

# Run clippy with all features
cargo clippy --all-features -- -D warnings
```

### Guidelines

- **Error handling**: Use `anyhow` for application errors, `thiserror` for library errors
- **Naming**: Use descriptive names; prefer clarity over brevity
- **Documentation**: Add doc comments for public APIs
- **Modules**: Keep modules focused and single-purpose
- **Dependencies**: Minimize new dependencies; justify additions in PRs

### Example Code Style

```rust
use anyhow::{Context, Result};

/// Processes the given input and returns a formatted result.
///
/// # Arguments
///
/// * `input` - The raw input string to process
///
/// # Errors
///
/// Returns an error if the input cannot be parsed.
pub fn process_input(input: &str) -> Result<String> {
    let parsed = parse(input)
        .context("Failed to parse input")?;
    
    Ok(format_output(parsed))
}
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_name

# Run tests in a specific module
cargo test module_name::
```

### Writing Tests

- Place unit tests in the same file as the code they test
- Use descriptive test names that explain what's being tested
- Test both success and failure cases
- Use `tempfile` for tests that need filesystem access

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_input_returns_expected_result() {
        let input = "valid input";
        let result = parse(input).unwrap();
        assert_eq!(result, expected_value);
    }

    #[test]
    fn parse_invalid_input_returns_error() {
        let input = "invalid";
        assert!(parse(input).is_err());
    }
}
```

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, no code change
- `refactor`: Code restructuring, no behavior change
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(review): add JSON output format

fix(login): handle expired tokens gracefully

docs(readme): update installation instructions

test(api): add integration tests for session endpoint
```

## Pull Request Process

1. **Ensure all tests pass**:
   ```bash
   cargo test
   cargo fmt --check
   cargo clippy -- -D warnings
   ```

2. **Update documentation** if needed (README, doc comments)

3. **Create a pull request** with:
   - Clear title following commit message conventions
   - Description of changes and motivation
   - Link to related issues (if any)

4. **Address review feedback** promptly

5. **Squash commits** if requested for cleaner history

### PR Checklist

- [ ] Tests pass locally
- [ ] Code is formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow conventions
- [ ] PR description explains the changes

## Reporting Bugs

Found a bug? Please [open an issue](https://github.com/unfault/cli/issues/new) with:

- **Clear title** describing the issue
- **Steps to reproduce** the bug
- **Expected behavior** vs actual behavior
- **Environment details**:
  - OS and version
  - Rust version (`rustc --version`)
  - Unfault version (`unfault --version`)
- **Relevant logs or error messages**

### Example Bug Report

```markdown
## Bug: Review command hangs on large repositories

### Steps to Reproduce
1. Clone a repository with 10,000+ files
2. Run `unfault review`
3. Command hangs indefinitely

### Expected Behavior
Review should complete or show progress

### Actual Behavior
No output, CPU at 100%

### Environment
- OS: Ubuntu 22.04
- Rust: 1.75.0
- Unfault: 0.1.0
```

## Suggesting Features

Have an idea? We'd love to hear it! [Open an issue](https://github.com/unfault/cli/issues/new) with:

- **Clear title** describing the feature
- **Problem statement**: What problem does this solve?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've thought about
- **Additional context**: Mockups, examples, references

---

## Questions?

- Open a [GitHub Discussion](https://github.com/unfault/cli/discussions)
- Check existing [issues](https://github.com/unfault/cli/issues) and [PRs](https://github.com/unfault/cli/pulls)

Thank you for contributing to Unfault! 🙏
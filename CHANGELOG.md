# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2025-12-23

### Added

- `unfault ask` now builds a local code graph and sends it with your RAG question, enabling flow-aware answers without uploading sources. Responses surface the HTTP route, call stack, and external dependency usage that shape the answer, so you can see exactly how a behavior is implemented.
- Flow responses now highlight graph impact details, topic labels, and hints, making it easier to decide the next question or code change straight from the CLI.
- Added the `UNFAULT_DUMP_IR` environment variable to persist the serialized IR produced during `unfault review`, which simplifies reproducing tricky analysis issues.

### Fixed

- `unfault ask` now auto-detects the workspace ID using the same heuristics as `graph` and `review`, ensuring queries are scoped to the current repo even when the flag is omitted.
- Local graph building now runs framework analysis for TypeScript/Express projects and properly builds Rust semantics before serialization, so the flow context remains accurate across languages.
- Flow path rendering now preserves the tree hierarchy of nested function calls, producing readable call stacks in the CLI output.

## [0.5.1] - 2025-12-21

### Fixed

- Fixed LSP server advertising pull diagnostics capability which caused "Method not found" errors
- Added hidden `--stdio` flag for compatibility with vscode-languageclient
- LSP now uses push diagnostics model via `publishDiagnostics` notifications

## [0.5.0] - 2025-12-21

### Added

- **LSP Server**: New `unfault lsp` command that starts a Language Server Protocol server for IDE integration
  - Provides real-time diagnostics as you code
  - Supports code actions with quick fixes from patches
  - Custom `unfault/fileCentrality` notification for status bar file importance display
  - Client-side parsing using tree-sitter (via unfault-core) for privacy and performance
  - Supports `--verbose` flag for debug logging
- New dependencies: `tower-lsp`, `dashmap`, `async-trait` for LSP implementation
- New `unfault graph refresh` command to build/refresh the code graph on-demand
- Graph building is now decoupled from review sessions for faster performance
- Improved hint messages in `unfault ask` when no graph data is available

### Changed

- Graph building no longer happens automatically during `unfault review`
- Users must now run `unfault graph refresh` before using graph-based features

## [0.4.0] - 2025-12-12

### Fixed

- Dimension filtering now correctly sends separate analysis contexts for each requested dimension
- Improved validation error handling with user-friendly messages for API errors

## [0.3.0] - 2025-12-10

### Added

- renamed `unfault.toml` to `.unfault.toml` for consistency with other tools

## [0.2.0] - 2025-12-10

### Added

- Code of conduct
- Installation note for pre-built releases in README
- SARIF support for review command output

## [0.1.1] - 2025-12-09

### Added

- Missing `license` field to Cargo.toml

## [0.1.0] - 2025-12-09

### Added

- Initial release of Unfault CLI — a calm reviewer for thoughtful engineers

[0.6.0]: https://github.com/unfault/cli/releases/tag/v0.6.0
[0.5.1]: https://github.com/unfault/cli/releases/tag/v0.5.1
[0.5.0]: https://github.com/unfault/cli/releases/tag/v0.5.0
[0.4.0]: https://github.com/unfault/cli/releases/tag/v0.4.0
[0.3.0]: https://github.com/unfault/cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/unfault/cli/releases/tag/v0.2.0
[0.1.1]: https://github.com/unfault/cli/releases/tag/v0.1.1
[0.1.0]: https://github.com/unfault/cli/releases/tag/v0.1.0

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.3] - 2026-01-15

### Added
- Added `start_line`/`end_line` to graph node serialization for function-scoped queries.
- Added `is_live` flag for function impact (LSP only).
- Added live session support and analysis complete notification.
- Added single-file refresh for instant findings update after quick fixes.
- Added friendly insights and path insights for sidebar.
- Added 'calls' field to FunctionImpactCaller for call chain tree visualization.
- Added function line range for scoped findings.
- Added `unfault graph refresh` command for on-demand graph building.
- Added default summary command with entry points and SLOs.
- Added affected routes and SLOs display in impact analysis.
- Added function centrality support in ask command.
- Added `workspace_mappings` to config for persistent workspace ID storage.

### Changed
- Softened insight messages to conversational tone.
- Use human-friendly insights instead of raw risk categories.
- LSP now runs analysis on save only, not on every keystroke.

### Fixed
- LSP now uses buffer content for analysis instead of reading from disk.
- LSP uses cached findings for function impact instead of API database.
- Fixed refresh dependencies notification on file change/save.
- Fixed route count reporting when linking SLOs.
- Improved impact analysis display formatting.
- Improved ask response quality with deduplication and code snippets.
- Fixed similarity percentage display capped at 99%.
- Embeddings are now generated after finalize for RAG search.
- Improved fallback messages when no context found.
- Improved ask command centrality query output phrasing.
- Fixed LSP workspace ID computation to read manifest files (matching CLI behavior).
- Fixed workspace ID stability when git remote is added to a project.

### Added
- Richer SLO context in `unfault ask`, including interactive mapping for service-level SLOs.
- New LSP diagnostics settings for server-side diagnostics control.

### Fixed
- Clearer guidance when GCP credentials expire and more robust GCP project detection.

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

[0.6.3]: https://github.com/unfault/cli/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/unfault/cli/releases/tag/v0.6.2
[0.6.0]: https://github.com/unfault/cli/releases/tag/v0.6.0
[0.5.1]: https://github.com/unfault/cli/releases/tag/v0.5.1
[0.5.0]: https://github.com/unfault/cli/releases/tag/v0.5.0
[0.4.0]: https://github.com/unfault/cli/releases/tag/v0.4.0
[0.3.0]: https://github.com/unfault/cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/unfault/cli/releases/tag/v0.2.0
[0.1.1]: https://github.com/unfault/cli/releases/tag/v0.1.1
[0.1.0]: https://github.com/unfault/cli/releases/tag/v0.1.0

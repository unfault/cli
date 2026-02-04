# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Use correct command hint to configure llm

## [0.6.27] - 2026-02-03

### Fixed

- `unfault graph`: avoid showing egress target ports as "Listens on" ports.
- `unfault graph`: resolve cross-workspace egress using local egress ports even when the persisted server session is older.
- `unfault graph`: show resolved target workspace name next to egress target when available.

## [0.6.26] - 2026-02-03

### Added

- `unfault review`: propagate detected `listening_ports` to the API during graph ingest (enables cross-workspace HTTP tracing).
- `unfault graph`: resolve outbound egress calls to known workspaces when the server has graph data (shows `service:port/path → service::handler`).

### Fixed

- `unfault graph`: format host remotes consistently (the graph emits host remotes without a `host:` prefix).
- Clippy warnings are now clean with `-D warnings`.

### Changed

- Bumped dependency on `unfault-core` to 0.1.19

## [0.6.25] - 2026-02-03

### Added

- `unfault graph`: show outbound HTTP egress calls under entrypoints (and include remote server nodes/HTTP call edges in the summary).

### Changed

- Bumped dependency on `unfault-core` to 0.1.18
  
## [0.6.24] - 2026-02-03

### Added

- `unfault ask`: render API-provided disambiguation candidates ("Possible targets") when a query can’t be resolved unambiguously.

### Changed

- `unfault addon fault plan`: add `-q/--quiet` to print only the runnable `fault run ...` command.
- Bumped dependency on `unfault-core` to 0.1.17

## [0.6.23] - 2026-02-02

### Changed

- `unfault addon fault plan` output is now more agent-friendly (ASCII, stable `key: value` hints, and a pointer to `--json`).
- Bumped dependency on `unfault-core` to 0.1.16

## [0.6.22] - 2026-02-02

### Added

- `unfault addon fault plan` and `unfault addon fault list` to generate runnable `fault run ...` commands from short recipes.
- `unfault review --llm`: top-level `next_steps` and `resilience_testing` alias to make fault injection guidance harder for agents to miss.

### Changed

- `unfault review --llm` fault injection templates now point to `unfault addon fault plan` (instead of raw `fault run ...` flags).

## [0.6.21] - 2026-01-29

### Fixed

- Rust semantics: use the full Rust semantics builder so Axum routes are detected (instead of returning an empty Rust semantics stub).

### Changed

- Bumped dependency on `unfault-core` to 0.1.15

## [0.6.20] - 2026-01-29

### Fixed

- API client: disable response compression (`Accept-Encoding: identity`) for IR analysis endpoints to avoid decode errors through some proxies/tunnels.
- IR analysis: handle `null` values for `line`/`column` fields in API responses (treats as 0).

### Changed

- Bumped dependency on `unfault-core` to 0.1.14 (uses local path for development).

## [0.6.19] - 2026-01-29

### Changed

- Fix version in Cargo.toml

## [0.6.18] - 2026-01-29

### Changed

- Bumped dependency on `unfault-core` to 0.1.12

## [0.6.17] - 2026-01-28

### Changed

- Bumped dependency on `unfault-core` to 0.1.11

## [0.6.16] - 2026-01-28

### Changed

- Bumped dependency on `unfault-core` to 0.1.10

## [0.6.15] - 2026-01-28

### Added

- LSP: return the outbound HTTP call under cursor (for egress fault injection UX)
- `unfault graph dump --semantics` for debugging extracted semantics

### Changed

- Bumped dependency on `unfault-core` to 0.1.9

## [0.6.12] - 2026-01-26

### Added

- Automatically append `.unfault/` to an existing repo `.gitignore` to prevent committing local cache data

## [0.6.11] - 2026-01-26

### Added

- New `unfault addon install fault` command to download and install the `fault` CLI
- `unfault status` now reports whether the `fault` addon is installed
- LSP can generate fault scenario suites

### Fixed

- Removed unsupported status link

## [0.6.10] - 2026-01-20

### Changed

- Review output now starts directly with narrative summary (no verbose header)
- Metadata moved to compact footer: `965ms - python / fastapi - 1 file`
- Cleaner, less "red team" appearance

## [0.6.9] - 2026-01-20

### Added

- `UNFAULT_API_KEY` environment variable support for CI/CD authentication
  - When set, the CLI uses this API key without requiring a config file
  - Works alongside `UNFAULT_BASE_URL` for custom API endpoints
  - Priority: environment variable takes precedence over config file

## [0.6.8] - 2026-01-16

### Added

- `unfault review --llm` now optionally includes SLO definitions when `--discover-observability` is enabled
  - Adds `slos` array with provider/targets/budget/timeframe details
  - Adds `summary.observability` with discovery coverage stats

### Changed

- CLI README is now intentionally short and docs-first (docs are the authority)

### Fixed

- CI now uses the published `unfault-core` crate by default (local `[patch.crates-io]` is commented out)
- Test expectations updated to match current user-facing messages
- `cargo fmt`/clippy hygiene fixes

## [0.6.5] - 2026-01-15

### Added

- New `--llm` flag for LLM-optimized JSON output designed for coding agents (Cursor, Copilot, Claude)
  - Compact schema with `stop_conditions` to prevent over-refactoring
  - `files_allowed_to_change` per finding for agent guardrails
  - Findings merged by rule+file and sorted by severity
- New `--uncommitted` flag to review only uncommitted files (staged, unstaged, untracked)
- New `--top N` flag to limit findings in LLM output (default 50, max 200)

### Changed

- `--file` flag now filters findings instead of limiting parsing, preserving full workspace context
- File filtering now works with `--output json`, `--output sarif`, and `--llm`

## [0.6.4] - 2026-01-15

### Changed

- Updated dependency on core 0.1.7

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

[Unreleased]: https://github.com/unfault/cli/compare/v0.6.22...HEAD
[0.6.22]: https://github.com/unfault/cli/compare/v0.6.21...v0.6.22
[0.6.17]: https://github.com/unfault/cli/compare/580bc99...HEAD
[0.6.16]: https://github.com/unfault/cli/compare/v0.6.12...580bc99
[0.6.15]: https://github.com/unfault/cli/compare/v0.6.12...7b03019
[0.6.12]: https://github.com/unfault/cli/compare/v0.6.11...v0.6.12
[0.6.11]: https://github.com/unfault/cli/compare/v0.6.10...v0.6.11
[0.6.10]: https://github.com/unfault/cli/compare/v0.6.9...v0.6.10
[0.6.9]: https://github.com/unfault/cli/compare/v0.6.8...v0.6.9
[0.6.8]: https://github.com/unfault/cli/compare/v0.6.5...v0.6.8
[0.6.5]: https://github.com/unfault/cli/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/unfault/cli/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/unfault/cli/compare/v0.6.0...v0.6.3
[0.6.0]: https://github.com/unfault/cli/releases/tag/v0.6.0
[0.5.1]: https://github.com/unfault/cli/releases/tag/v0.5.1
[0.5.0]: https://github.com/unfault/cli/releases/tag/v0.5.0
[0.4.0]: https://github.com/unfault/cli/releases/tag/v0.4.0
[0.3.0]: https://github.com/unfault/cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/unfault/cli/releases/tag/v0.2.0
[0.1.1]: https://github.com/unfault/cli/releases/tag/v0.1.1
[0.1.0]: https://github.com/unfault/cli/releases/tag/v0.1.0

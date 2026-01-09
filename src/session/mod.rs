//! # Session Management
//!
//! This module handles the complete session lifecycle for code analysis:
//!
//! 1. **Workspace scanning** - Detect project type, languages, and frameworks
//! 2. **File collection** - Apply file hints/patterns to select files for analysis
//! 3. **Session execution** - Create session, run analysis, and wait for results
//!
//! ## Architecture
//!
//! The session module separates concerns from the API layer:
//! - `api/session.rs` - HTTP calls and request/response types
//! - `session/` - Business logic for workspace scanning and session orchestration
//!
//! ## Usage
//!
//! ```rust,ignore
//! use unfault::session::{WorkspaceScanner, FileCollector, SessionRunner};
//!
//! // 1. Scan workspace
//! let scanner = WorkspaceScanner::new(&workspace_path);
//! let workspace_info = scanner.scan()?;
//!
//! // 2. Create session and get file hints
//! let runner = SessionRunner::new(api_client, api_key);
//! let session = runner.create_session(&workspace_info).await?;
//!
//! // 3. Collect files based on hints
//! let collector = FileCollector::new(&workspace_path);
//! let files = collector.collect(&session.file_hints)?;
//!
//! // 4. Run analysis and wait for results
//! let results = runner.run_analysis(&session.session_id, &workspace_info, files).await?;
//! ```

pub mod file_collector;
pub mod graph_builder;
pub mod header_extractor;
pub mod ir_builder;
pub mod patch_applier;
pub mod runner;
pub mod semantics_cache;
pub mod workspace;
pub mod workspace_id;
pub mod workspace_settings;

pub use file_collector::FileCollector;
pub use graph_builder::{SerializableGraph, build_local_graph};
pub use header_extractor::{FileHeader, HeaderExtractor, HeaderExtractorConfig};
pub use ir_builder::{IrBuildResult, build_ir, build_ir_cached};
pub use patch_applier::{PatchApplier, PatchStats};
pub use runner::SessionRunner;
pub use semantics_cache::{CacheStats, SemanticsCache};
pub use workspace::{
    DetectedFramework, ProgressCallback, ScanProgress, WorkspaceInfo, WorkspaceScanner,
};
pub use workspace_id::{
    MetaFileInfo, PackageExport, WorkspaceIdResult, WorkspaceIdSource, compute_file_id,
    compute_symbol_id, compute_workspace_id, extract_package_export, get_git_remote,
    normalize_git_remote, normalize_rel_path,
};
pub use workspace_settings::{
    LoadedSettings, RuleSettings, SettingsSource, WorkspaceSettings, load_settings,
};

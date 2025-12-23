//! Semantics cache for accelerating repeated analysis runs.
//!
//! This module provides a file-based cache for parsed semantics. When a file
//! hasn't changed (same content hash), we can skip re-parsing and use the
//! cached semantics instead.
//!
//! ## Design
//!
//! - Cache key: (relative_path, content_hash_xxh3_64)
//! - Cache value: MessagePack-serialized SourceSemantics
//! - Storage: `.unfault/cache/semantics/<hash>.msgpack`
//! - Invalidation: Content hash mismatch or cache version bump
//!
//! ## Performance
//!
//! - xxh3 hashing: ~6GB/s (vs ~500MB/s for SHA-256)
//! - MessagePack: 2-10x smaller than JSON, faster to serialize
//! - Expected: ~50-100ms for warm cache vs ~2000ms for cold parse

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use xxhash_rust::xxh3::xxh3_64;

use unfault_core::semantics::SourceSemantics;

/// Current cache format version. Bump this when semantics structure changes.
const CACHE_VERSION: u32 = 1;

/// Cache metadata stored in meta.json
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CacheMeta {
    version: u32,
    created_at: u64,
}

/// Entry in the in-memory cache index
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Path to the cached file
    cache_path: PathBuf,
    /// Content hash of the source file
    content_hash: u64,
}

/// Statistics about cache usage during a build
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of files with cache hits
    pub hits: usize,
    /// Number of files with cache misses (had to parse)
    pub misses: usize,
    /// Total bytes saved by using cache
    pub bytes_saved: usize,
}

impl CacheStats {
    /// Returns the hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// A file-based cache for parsed semantics.
///
/// The cache stores semantics indexed by (path_hash, content_hash).
/// When a file's content hash matches, we can skip parsing.
#[derive(Debug)]
pub struct SemanticsCache {
    /// Root directory of the cache (e.g., `.unfault/cache/semantics`)
    cache_dir: PathBuf,
    /// In-memory index: path_hash -> CacheEntry
    index: HashMap<u64, CacheEntry>,
    /// Statistics for this session
    stats: CacheStats,
    /// Whether the cache is enabled
    enabled: bool,
}

impl SemanticsCache {
    /// Open or create a cache in the given workspace directory.
    ///
    /// Creates `.unfault/cache/semantics/` if it doesn't exist.
    pub fn open(workspace_path: &Path) -> Result<Self> {
        let cache_dir = workspace_path.join(".unfault").join("cache").join("semantics");
        
        // Create cache directory if it doesn't exist
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)
                .context("Failed to create cache directory")?;
        }
        
        // Check cache version
        let meta_path = cache_dir.join("meta.json");
        let should_clear = if meta_path.exists() {
            let meta: CacheMeta = serde_json::from_reader(
                BufReader::new(fs::File::open(&meta_path)?)
            ).unwrap_or(CacheMeta { version: 0, created_at: 0 });
            
            meta.version != CACHE_VERSION
        } else {
            false
        };
        
        if should_clear {
            // Clear old cache
            for entry in fs::read_dir(&cache_dir)? {
                let entry = entry?;
                if entry.path().extension().map_or(false, |e| e == "msgpack") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        
        // Write current version
        let meta = CacheMeta {
            version: CACHE_VERSION,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let meta_file = fs::File::create(&meta_path)?;
        serde_json::to_writer(BufWriter::new(meta_file), &meta)?;
        
        // Build index from existing cache files
        let mut index = HashMap::new();
        for entry in fs::read_dir(&cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "msgpack") {
                // Parse filename: <content_hash>_<path_hash>_<truncated_path>.msgpack
                let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let parts: Vec<&str> = filename.splitn(3, '_').collect();
                if parts.len() >= 2 {
                    if let (Ok(content_hash), Ok(path_hash)) = (
                        u64::from_str_radix(parts[0], 16),
                        u64::from_str_radix(parts[1], 16),
                    ) {
                        index.insert(path_hash, CacheEntry {
                            cache_path: path.clone(),
                            content_hash,
                        });
                    }
                }
            }
        }
        
        Ok(Self {
            cache_dir,
            index,
            stats: CacheStats::default(),
            enabled: true,
        })
    }
    
    /// Create a disabled cache (always returns None for lookups)
    pub fn disabled() -> Self {
        Self {
            cache_dir: PathBuf::new(),
            index: HashMap::new(),
            stats: CacheStats::default(),
            enabled: false,
        }
    }
    
    /// Compute the content hash of file content.
    pub fn hash_content(content: &str) -> u64 {
        xxh3_64(content.as_bytes())
    }
    
    /// Try to get cached semantics for a file.
    ///
    /// Returns `Some(semantics)` if the file is in the cache and the content
    /// hash matches. Returns `None` if there's a cache miss.
    pub fn get(&mut self, relative_path: &str, content_hash: u64) -> Option<SourceSemantics> {
        if !self.enabled {
            return None;
        }
        
        // Compute path hash for lookup
        let path_hash = xxh3_64(relative_path.as_bytes());
        
        let entry = match self.index.get(&path_hash) {
            Some(e) => e,
            None => {
                // No entry in index = cache miss
                self.stats.misses += 1;
                return None;
            }
        };
        
        // Check if content hash matches
        if entry.content_hash != content_hash {
            self.stats.misses += 1;
            return None;
        }
        
        // Try to read from cache file
        let file = fs::File::open(&entry.cache_path).ok()?;
        let reader = BufReader::new(file);
        
        match rmp_serde::from_read(reader) {
            Ok(semantics) => {
                self.stats.hits += 1;
                Some(semantics)
            }
            Err(_) => {
                // Cache file corrupted, treat as miss
                self.stats.misses += 1;
                None
            }
        }
    }
    
    /// Store semantics in the cache.
    pub fn set(&mut self, relative_path: &str, content_hash: u64, semantics: &SourceSemantics) {
        if !self.enabled {
            return;
        }
        
        // Compute path hash for indexing
        let path_hash = xxh3_64(relative_path.as_bytes());
        
        // Generate cache filename: <content_hash>_<path_hash>_<truncated_path>.msgpack
        // We include the truncated path for debugging/readability
        let safe_path = relative_path.replace(['/', '\\', ':'], "_");
        let truncated_path: String = safe_path.chars().take(50).collect();
        let filename = format!("{:016x}_{:016x}_{}.msgpack", content_hash, path_hash, truncated_path);
        let cache_path = self.cache_dir.join(&filename);
        
        // Serialize and write
        if let Ok(file) = fs::File::create(&cache_path) {
            let mut writer = BufWriter::new(file);
            if rmp_serde::encode::write(&mut writer, semantics).is_ok() {
                // Update index using path_hash as key
                self.index.insert(path_hash, CacheEntry {
                    cache_path,
                    content_hash,
                });
            }
        }
    }
    
    /// Record a cache miss (for stats tracking when we skip the cache lookup)
    pub fn record_miss(&mut self) {
        self.stats.misses += 1;
    }
    
    /// Get cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }
    
    /// Clear the cache.
    pub fn clear(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.path().extension().map_or(false, |e| e == "msgpack") {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use unfault_core::parse::ast::FileId;
    use unfault_core::parse::python;
    use unfault_core::semantics::python::model::PyFileSemantics;
    use unfault_core::types::context::{Language, SourceFile};
    
    /// Create a simple Python semantics for testing
    fn create_test_semantics() -> SourceSemantics {
        let source_file = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: "def hello():\n    pass\n".to_string(),
        };
        let parsed = python::parse_python_file(FileId(1), &source_file).unwrap();
        let sem = PyFileSemantics::from_parsed(&parsed);
        SourceSemantics::Python(sem)
    }
    
    #[test]
    fn test_hash_content() {
        let hash1 = SemanticsCache::hash_content("hello world");
        let hash2 = SemanticsCache::hash_content("hello world");
        let hash3 = SemanticsCache::hash_content("hello world!");
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_cache_miss_on_empty() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
        
        let result = cache.get("test.py", 12345);
        assert!(result.is_none());
        assert_eq!(cache.stats().misses, 1);
    }
    
    #[test]
    fn test_cache_hit() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
        
        let semantics = create_test_semantics();
        let content_hash = 12345u64;
        
        cache.set("test.py", content_hash, &semantics);
        
        let result = cache.get("test.py", content_hash);
        assert!(result.is_some());
        assert_eq!(cache.stats().hits, 1);
    }
    
    #[test]
    fn test_cache_miss_on_hash_change() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
        
        let semantics = create_test_semantics();
        
        cache.set("test.py", 12345, &semantics);
        
        // Different hash should miss
        let result = cache.get("test.py", 99999);
        assert!(result.is_none());
        assert_eq!(cache.stats().misses, 1);
    }
    
    #[test]
    fn test_cache_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let content_hash = 12345u64;
        
        // Write to cache
        {
            let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
            let semantics = create_test_semantics();
            cache.set("test.py", content_hash, &semantics);
        }
        
        // Read from cache with new instance
        {
            let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
            let result = cache.get("test.py", content_hash);
            assert!(result.is_some());
        }
    }
    
    #[test]
    fn test_hit_rate() {
        let stats = CacheStats {
            hits: 80,
            misses: 20,
            bytes_saved: 0,
        };
        assert!((stats.hit_rate() - 80.0).abs() < 0.01);
    }
    
    #[test]
    fn test_disabled_cache() {
        let mut cache = SemanticsCache::disabled();
        
        let semantics = create_test_semantics();
        cache.set("test.py", 12345, &semantics);
        
        let result = cache.get("test.py", 12345);
        assert!(result.is_none());
    }
}

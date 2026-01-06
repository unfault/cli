//! Chunked (resumable) semantics encoding for `/api/v1/graph/analyze/chunk`.
//!
//! Wire format per chunk (same as graph ingest):
//! - Body is zstd-compressed
//! - Decompressed payload is a sequence of framed msgpack records:
//!   - `u32` big-endian length prefix
//!   - msgpack payload (map)
//!
//! Each chunk MUST end with a `chunk_done` control record that includes:
//! - seq
//! - files count in the chunk
//! - checksum: xxh3_64 of all framed bytes before chunk_done

use serde::Serialize;
use unfault_core::SourceSemantics;
use xxhash_rust::xxh3::Xxh3;

/// Target chunk size in compressed bytes (~1MB to stay well under memory limits)
pub const TARGET_CHUNK_BYTES: usize = 1024 * 1024;

/// Per-file semantics record
#[derive(Serialize)]
struct FileRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,

    file_path: &'a str,
    language: &'static str,
    semantics: serde_json::Value,
}

/// Control record marking end of chunk
#[derive(Serialize)]
struct ChunkDoneRecord {
    #[serde(rename = "type")]
    record_type: &'static str,
    event: &'static str,

    seq: u32,
    files: u32,
    checksum: u64,
}

/// Result of encoding a chunk
pub struct EncodedChunk {
    /// Compressed bytes to send
    pub data: Vec<u8>,
    /// Number of files in this chunk
    pub file_count: usize,
    /// Whether this is the last chunk
    pub is_last: bool,
}

fn push_frame(buf: &mut Vec<u8>, value: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let payload = rmp_serde::to_vec_named(value)?;
    let len = u32::try_from(payload.len())?;

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);

    buf.extend_from_slice(&frame);
    Ok(frame)
}

fn language_to_str(sem: &SourceSemantics) -> &'static str {
    match sem {
        SourceSemantics::Python(_) => "python",
        SourceSemantics::Go(_) => "go",
        SourceSemantics::Rust(_) => "rust",
        SourceSemantics::Typescript(_) => "typescript",
    }
}

/// Encode a chunk of semantics records.
///
/// # Arguments
/// * `semantics` - Full list of semantics
/// * `start` - Starting index in the semantics slice
/// * `max_files` - Maximum number of files to include in this chunk
/// * `seq` - Sequence number for this chunk
///
/// # Returns
/// Compressed chunk data with checksum, ready to send to API
pub fn encode_semantics_chunk(
    semantics: &[SourceSemantics],
    start: usize,
    max_files: usize,
    seq: u32,
) -> anyhow::Result<EncodedChunk> {
    let mut raw = Vec::with_capacity(2 * 1024 * 1024); // Start with 2MB capacity
    let mut hasher = Xxh3::new();

    let end = (start + max_files).min(semantics.len());
    let mut files = 0u32;

    for sem in &semantics[start..end] {
        // Serialize semantics to JSON value
        let semantics_value = serde_json::to_value(sem)?;

        let frame = push_frame(
            &mut raw,
            &FileRecord {
                record_type: "file",
                file_path: sem.file_path(),
                language: language_to_str(sem),
                semantics: semantics_value,
            },
        )?;

        hasher.update(&frame);
        files += 1;
    }

    let checksum = hasher.digest();

    // Add the control record (not included in checksum)
    push_frame(
        &mut raw,
        &ChunkDoneRecord {
            record_type: "control",
            event: "chunk_done",
            seq,
            files,
            checksum,
        },
    )?;

    let compressed = zstd::stream::encode_all(std::io::Cursor::new(raw), 3)?;
    let is_last = end >= semantics.len();

    Ok(EncodedChunk {
        data: compressed,
        file_count: files as usize,
        is_last,
    })
}

/// Iterator that yields semantics chunks based on compressed size target.
///
/// This adaptively determines chunk boundaries to stay near TARGET_CHUNK_BYTES
/// while ensuring progress is made (at least 1 file per chunk).
pub struct SemanticsChunker<'a> {
    semantics: &'a [SourceSemantics],
    current_index: usize,
    seq: u32,
    // Adaptive: start with estimate, adjust based on actual sizes
    files_per_chunk: usize,
}

impl<'a> SemanticsChunker<'a> {
    pub fn new(semantics: &'a [SourceSemantics]) -> Self {
        // Start with a conservative estimate: ~100 files per MB chunk
        // Will adjust based on actual compressed sizes
        let initial_estimate = 100.min(semantics.len().max(1));

        Self {
            semantics,
            current_index: 0,
            seq: 0,
            files_per_chunk: initial_estimate,
        }
    }

    /// Returns total number of files
    pub fn total_files(&self) -> usize {
        self.semantics.len()
    }

    /// Returns number of files processed so far
    pub fn files_processed(&self) -> usize {
        self.current_index
    }

    /// Get next chunk, or None if done
    pub fn next_chunk(&mut self) -> anyhow::Result<Option<EncodedChunk>> {
        if self.current_index >= self.semantics.len() {
            return Ok(None);
        }

        let chunk = encode_semantics_chunk(
            self.semantics,
            self.current_index,
            self.files_per_chunk,
            self.seq,
        )?;

        // Adjust files_per_chunk based on actual compressed size
        let actual_size = chunk.data.len();
        if actual_size > 0 && chunk.file_count > 0 {
            // Estimate: (files_in_chunk / actual_size) * TARGET_CHUNK_BYTES
            let estimated_optimal =
                (chunk.file_count as f64 * TARGET_CHUNK_BYTES as f64 / actual_size as f64) as usize;
            // Clamp to reasonable bounds and smooth the adjustment
            let new_estimate = estimated_optimal.clamp(1, 1000);
            // Smooth: move 50% toward new estimate
            self.files_per_chunk = (self.files_per_chunk + new_estimate) / 2;
            self.files_per_chunk = self.files_per_chunk.max(1);
        }

        self.current_index += chunk.file_count;
        self.seq += 1;

        Ok(Some(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_frames(mut data: &[u8]) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while data.len() >= 4 {
            let len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
            data = &data[4..];
            if data.len() < len {
                break;
            }
            let payload = &data[..len];
            data = &data[len..];
            let v: serde_json::Value = rmp_serde::from_slice(payload).unwrap();
            out.push(v);
        }
        out
    }

    #[test]
    fn empty_semantics_returns_empty_chunk() {
        let semantics: Vec<SourceSemantics> = vec![];
        let chunk = encode_semantics_chunk(&semantics, 0, 10, 0).unwrap();

        assert_eq!(chunk.file_count, 0);
        assert!(chunk.is_last);

        // Decompress and verify control record
        let decoded = zstd::stream::decode_all(std::io::Cursor::new(&chunk.data)).unwrap();
        let frames = decode_frames(&decoded);

        assert_eq!(frames.len(), 1); // Just the control record
        assert_eq!(frames[0]["type"], "control");
        assert_eq!(frames[0]["event"], "chunk_done");
        assert_eq!(frames[0]["files"], 0);
    }

    #[test]
    fn chunker_with_empty_semantics() {
        let semantics: Vec<SourceSemantics> = vec![];
        let mut chunker = SemanticsChunker::new(&semantics);

        assert_eq!(chunker.total_files(), 0);
        let chunk = chunker.next_chunk().unwrap();
        assert!(chunk.is_none());
    }
}

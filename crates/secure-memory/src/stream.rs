//! Stream — chunked encrypted in-memory container.
//!
//! Data is written in chunks, each independently encrypted with the session
//! key. On read, chunks are decrypted on demand. This allows handling large
//! datasets without ever holding the entire plaintext in memory at once.

use std::collections::VecDeque;
use std::sync::Mutex;

use zeroize::Zeroize;

use crate::crypto;
use crate::error::Error;

/// Default chunk size: 4 memory pages (typically 16 KiB).
const DEFAULT_CHUNK_SIZE: usize = 4 * 4096;

/// An encrypted in-memory stream.
///
/// Data flows in as plaintext, is encrypted in fixed-size chunks, and flows
/// out as plaintext again — each chunk decrypted only when read.
pub struct Stream {
    /// Queue of encrypted chunks.
    chunks: Mutex<VecDeque<Vec<u8>>>,
    /// Maximum plaintext bytes per chunk.
    chunk_size: usize,
    /// Accumulates data until a full chunk is ready.
    write_buf: Mutex<Vec<u8>>,
}

impl Stream {
    /// Create a stream with the default chunk size (16 KiB).
    pub fn new() -> Self {
        Self::with_chunk_size(DEFAULT_CHUNK_SIZE)
    }

    /// Create a stream with a custom chunk size.
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Stream {
            chunks: Mutex::new(VecDeque::new()),
            chunk_size,
            write_buf: Mutex::new(Vec::new()),
        }
    }

    /// Write plaintext into the stream.
    ///
    /// Data accumulates internally; once a full chunk is collected it is
    /// encrypted and queued. Call [`flush`](Self::flush) to encrypt any
    /// remaining partial chunk.
    pub fn write(&self, data: &[u8]) -> Result<(), Error> {
        let mut buf = self.write_buf.lock().unwrap_or_else(|e| e.into_inner());
        buf.extend_from_slice(data);

        while buf.len() >= self.chunk_size {
            let mut chunk: Vec<u8> = buf.drain(..self.chunk_size).collect();
            let encrypted = crypto::session_encrypt(&chunk)?;
            chunk.zeroize();
            self.chunks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_back(encrypted);
        }

        Ok(())
    }

    /// Encrypt and queue any remaining data in the write buffer.
    pub fn flush(&self) -> Result<(), Error> {
        let mut buf = self.write_buf.lock().unwrap_or_else(|e| e.into_inner());
        if !buf.is_empty() {
            let encrypted = crypto::session_encrypt(&buf)?;
            buf.zeroize();
            buf.clear();
            self.chunks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_back(encrypted);
        }
        Ok(())
    }

    /// Read and decrypt the next chunk. Returns `None` when empty.
    pub fn read(&self) -> Result<Option<Vec<u8>>, Error> {
        let encrypted = self
            .chunks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front();
        match encrypted {
            Some(enc) => Ok(Some(crypto::session_decrypt(&enc)?)),
            None => Ok(None),
        }
    }

    /// `true` if no encrypted chunks remain and the write buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.chunks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
            && self
                .write_buf
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
    }

    /// Number of encrypted chunks queued for reading.
    pub fn chunk_count(&self) -> usize {
        self.chunks.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_flush_read_roundtrip() {
        let s = Stream::with_chunk_size(16);
        s.write(b"hello, stream!!!").unwrap(); // exactly 16 bytes → 1 chunk
        s.flush().unwrap();

        let mut out = Vec::new();
        while let Some(chunk) = s.read().unwrap() {
            out.extend_from_slice(&chunk);
        }
        assert_eq!(out, b"hello, stream!!!");
    }

    #[test]
    fn multi_chunk() {
        let s = Stream::with_chunk_size(8);
        s.write(b"aaaaaaaabbbbbbbbcccc").unwrap(); // 20 bytes → 2 full + 4 pending
        s.flush().unwrap(); // flush the remaining 4

        let mut out = Vec::new();
        while let Some(chunk) = s.read().unwrap() {
            out.extend_from_slice(&chunk);
        }
        assert_eq!(out, b"aaaaaaaabbbbbbbbcccc");
    }

    #[test]
    fn empty_stream() {
        let s = Stream::new();
        assert!(s.is_empty());
        assert!(s.read().unwrap().is_none());
    }
}

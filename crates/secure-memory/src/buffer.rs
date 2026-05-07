//! LockedBuffer — the core secure memory primitive.
//!
//! Memory layout:
//! ```text
//! [guard page PROT_NONE] [canary | user data | canary | pad] [guard page PROT_NONE]
//!                         ^─────── inner (mlock'd) ────────^
//! ```

use std::sync::{LazyLock, Mutex};

use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::Error;
use crate::platform;

/// Size of each canary sentinel (bytes).
const CANARY_SIZE: usize = 32;

/// Per-process canary value, generated once from CSPRNG.
static CANARY: LazyLock<[u8; CANARY_SIZE]> = LazyLock::new(|| {
    let mut c = [0u8; CANARY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut c);
    c
});

/// Global registry of live allocations — used by [`purge_all`].
static REGISTRY: LazyLock<Mutex<Vec<AllocationMeta>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Metadata stashed in the registry so `purge_all` can wipe without
/// needing a reference to the owning `LockedBuffer`.
#[derive(Clone)]
struct AllocationMeta {
    /// Start of the full mmap region (as usize for Send).
    base: usize,
    total_size: usize,
    /// Start of the inner (locked) region.
    inner: usize,
    inner_size: usize,
    /// Start of the user-visible data.
    data: usize,
    data_len: usize,
}

// usize is Send + Sync, so AllocationMeta is too.

// ── LockedBuffer ─────────────────────────────────────────────

/// A buffer of sensitive data protected by multiple layers:
///
/// * **Guard pages** — inaccessible memory before and after the data region;
///   any overflow triggers a segfault.
/// * **Memory locking** — `mlock` / `VirtualLock` pins pages in RAM,
///   preventing the kernel from swapping them to disk.
/// * **Canary values** — cryptographic sentinels detect buffer overruns.
/// * **Access control** — `freeze` / `melt` toggle kernel-level write
///   protection (read-only vs read-write).
/// * **Secure wiping** — data is zeroed via [`zeroize`] on drop, defeating
///   dead-store elimination.
pub struct LockedBuffer {
    meta: AllocationMeta,
    frozen: bool,
    alive: bool,
}

// LockedBuffer owns a unique allocation — safe to send across threads.
// NOT Sync: concurrent access requires external synchronisation.
unsafe impl Send for LockedBuffer {}

impl LockedBuffer {
    // ── Constructors ─────────────────────────────────────────

    /// Create a zero-filled mutable buffer of `size` bytes.
    pub fn new(size: usize) -> Result<Self, Error> {
        Self::check_size(size)?;
        Self::allocate(size, |ptr, len| unsafe {
            std::ptr::write_bytes(ptr, 0, len);
        })
    }

    /// Create a buffer containing a copy of `data`, then **freeze** it
    /// (read-only). The caller is responsible for wiping the source.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::check_size(data.len())?;
        let mut buf = Self::allocate(data.len(), |ptr, len| unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len);
        })?;
        buf.freeze()?;
        Ok(buf)
    }

    /// Like [`from_bytes`](Self::from_bytes), but wipes the source after copy.
    pub fn from_bytes_move(data: &mut [u8]) -> Result<Self, Error> {
        let buf = Self::from_bytes(data)?;
        data.zeroize();
        Ok(buf)
    }

    /// Create a buffer filled with `size` bytes of CSPRNG output.
    pub fn random(size: usize) -> Result<Self, Error> {
        Self::check_size(size)?;
        Self::allocate(size, |ptr, len| {
            let s = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
            rand::rngs::OsRng.fill_bytes(s);
        })
    }

    // ── Accessors ────────────────────────────────────────────

    /// Borrow the data as a read-only slice.
    pub fn as_slice(&self) -> Result<&[u8], Error> {
        self.check_alive()?;
        Ok(unsafe { std::slice::from_raw_parts(self.meta.data as *const u8, self.meta.data_len) })
    }

    /// Borrow the data as a mutable slice. Fails if frozen.
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8], Error> {
        self.check_alive()?;
        if self.frozen {
            return Err(Error::Frozen);
        }
        Ok(
            unsafe {
                std::slice::from_raw_parts_mut(self.meta.data as *mut u8, self.meta.data_len)
            },
        )
    }

    /// Number of user-data bytes.
    pub fn len(&self) -> usize {
        self.meta.data_len
    }

    pub fn is_empty(&self) -> bool {
        self.meta.data_len == 0
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    // ── Access control ───────────────────────────────────────

    /// Make the buffer read-only at the kernel level.
    pub fn freeze(&mut self) -> Result<(), Error> {
        self.check_alive()?;
        if !self.frozen {
            unsafe {
                platform::protect_read(self.meta.inner as *mut u8, self.meta.inner_size)?;
            }
            self.frozen = true;
        }
        Ok(())
    }

    /// Restore read-write access.
    pub fn melt(&mut self) -> Result<(), Error> {
        self.check_alive()?;
        if self.frozen {
            unsafe {
                platform::protect_rw(self.meta.inner as *mut u8, self.meta.inner_size)?;
            }
            self.frozen = false;
        }
        Ok(())
    }

    // ── Data operations ──────────────────────────────────────

    /// Copy `src` into the buffer (constant-time). Lengths must match.
    pub fn copy_from(&mut self, src: &[u8]) -> Result<(), Error> {
        self.check_alive()?;
        if self.frozen {
            return Err(Error::Frozen);
        }
        let dst = self.as_mut_slice()?;
        if src.len() != dst.len() {
            return Err(Error::InvalidSize(format!(
                "expected {} bytes, got {}",
                dst.len(),
                src.len()
            )));
        }
        dst.copy_from_slice(src);
        Ok(())
    }

    /// Copy `src` into the buffer, then wipe the source.
    pub fn move_from(&mut self, src: &mut [u8]) -> Result<(), Error> {
        self.copy_from(src)?;
        src.zeroize();
        Ok(())
    }

    /// Overwrite contents with CSPRNG output.
    pub fn scramble(&mut self) -> Result<(), Error> {
        self.check_alive()?;
        let was_frozen = self.frozen;
        if was_frozen {
            self.melt()?;
        }
        {
            let s = self.as_mut_slice()?;
            rand::rngs::OsRng.fill_bytes(s);
        }
        if was_frozen {
            self.freeze()?;
        }
        Ok(())
    }

    /// Overwrite contents with zeros.
    pub fn wipe(&mut self) -> Result<(), Error> {
        self.check_alive()?;
        let was_frozen = self.frozen;
        if was_frozen {
            self.melt()?;
        }
        {
            let s = self.as_mut_slice()?;
            s.zeroize();
        }
        if was_frozen {
            self.freeze()?;
        }
        Ok(())
    }

    /// Encrypt the buffer into an [`Enclave`](crate::enclave::Enclave),
    /// consuming and wiping this buffer.
    pub fn seal(self) -> Result<crate::enclave::Enclave, Error> {
        let slice = self.as_slice()?;
        let enclave = crate::enclave::Enclave::new(slice)?;
        // `self` is dropped here → destroy() wipes and frees.
        Ok(enclave)
    }

    /// Constant-time equality comparison.
    pub fn ct_eq(&self, other: &LockedBuffer) -> Result<bool, Error> {
        self.check_alive()?;
        other.check_alive()?;
        let a = self.as_slice()?;
        let b = other.as_slice()?;
        if a.len() != b.len() {
            return Ok(false);
        }
        Ok(a.ct_eq(b).into())
    }

    // ── Internals ────────────────────────────────────────────

    fn check_size(size: usize) -> Result<(), Error> {
        if size == 0 {
            return Err(Error::InvalidSize("size must be > 0".into()));
        }
        Ok(())
    }

    fn check_alive(&self) -> Result<(), Error> {
        if !self.alive {
            Err(Error::Destroyed)
        } else {
            Ok(())
        }
    }

    /// Core allocation routine. Sets up guard pages, canaries, mlock.
    fn allocate(size: usize, init: impl FnOnce(*mut u8, usize)) -> Result<Self, Error> {
        let page = platform::page_size();
        // inner = canary + data + canary, rounded to page boundary
        let inner_size = platform::round_up(CANARY_SIZE + size + CANARY_SIZE, page);
        // total = pre-guard + inner + post-guard
        let total_size = page + inner_size + page;

        unsafe {
            let base = platform::alloc_mem(total_size)?;

            // Guard pages: PROT_NONE
            platform::protect_none(base, page)?;
            platform::protect_none(base.add(page + inner_size), page)?;

            // Lock inner region into RAM
            let inner = base.add(page);
            platform::lock(inner, inner_size)?;

            // Exclude from core dumps
            platform::dont_dump(inner, inner_size);

            // Write canaries
            let canary = &*CANARY;
            let pre = inner;
            let post = inner.add(CANARY_SIZE + size);
            std::ptr::copy_nonoverlapping(canary.as_ptr(), pre, CANARY_SIZE);
            std::ptr::copy_nonoverlapping(canary.as_ptr(), post, CANARY_SIZE);

            // User data sits between the two canaries
            let data = inner.add(CANARY_SIZE);
            init(data, size);

            let meta = AllocationMeta {
                base: base as usize,
                total_size,
                inner: inner as usize,
                inner_size,
                data: data as usize,
                data_len: size,
            };

            // Register for purge_all()
            REGISTRY
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(meta.clone());

            Ok(LockedBuffer {
                meta,
                frozen: false,
                alive: true,
            })
        }
    }

    /// Verify that the canary sentinels are intact.
    fn verify_canaries(&self) -> bool {
        let canary = &*CANARY;
        unsafe {
            let inner = self.meta.inner as *const u8;
            let pre = std::slice::from_raw_parts(inner, CANARY_SIZE);
            let post = std::slice::from_raw_parts(
                inner.add(CANARY_SIZE + self.meta.data_len),
                CANARY_SIZE,
            );
            bool::from(pre.ct_eq(canary)) && bool::from(post.ct_eq(canary))
        }
    }

    /// Wipe, unlock, and free the backing allocation.
    fn destroy(&mut self) {
        if !self.alive {
            return;
        }

        // Check canaries before cleanup
        if !self.verify_canaries() {
            eprintln!(
                "secure-memory: CANARY VIOLATION at buffer {:p} (possible overflow)",
                self.meta.data as *const u8
            );
        }

        unsafe {
            // Make inner writable for wipe
            let _ = platform::protect_rw(self.meta.inner as *mut u8, self.meta.inner_size);

            // Wipe entire inner region (canaries + data + padding)
            let inner =
                std::slice::from_raw_parts_mut(self.meta.inner as *mut u8, self.meta.inner_size);
            inner.zeroize();

            // Unlock
            platform::unlock(self.meta.inner as *mut u8, self.meta.inner_size);

            // Free the entire region (munmap handles guard pages too)
            platform::free_mem(self.meta.base as *mut u8, self.meta.total_size);
        }

        self.alive = false;

        // Deregister
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.retain(|m| m.base != self.meta.base);
        }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.destroy();
    }
}

// ── Global operations ────────────────────────────────────────

/// Wipe every live LockedBuffer's data in-place, then destroy the session
/// encryption key (making all Enclaves permanently undecryptable).
///
/// Individual `LockedBuffer` objects remain allocated and will be properly
/// freed when they are dropped. This function is the "nuclear" cleanup
/// option — call it on shutdown or in response to a threat signal.
///
/// **Not safe to call concurrently** with buffer reads in other threads.
pub fn purge_all() {
    // Step 1: destroy the session key first (its LockedBuffer is deregistered
    // via Drop, so the lock is released between these two steps).
    crate::crypto::destroy_session_key();

    // Step 2: wipe all remaining registered buffers.
    if let Ok(reg) = REGISTRY.lock() {
        for meta in reg.iter() {
            unsafe {
                let _ = platform::protect_rw(meta.inner as *mut u8, meta.inner_size);
                let inner = std::slice::from_raw_parts_mut(meta.inner as *mut u8, meta.inner_size);
                inner.zeroize();
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buffer_is_zeroed() {
        let buf = LockedBuffer::new(64).unwrap();
        let s = buf.as_slice().unwrap();
        assert_eq!(s.len(), 64);
        assert!(s.iter().all(|&b| b == 0));
    }

    #[test]
    fn from_bytes_freezes() {
        let buf = LockedBuffer::from_bytes(b"hello secure world").unwrap();
        assert!(buf.is_frozen());
        assert_eq!(buf.as_slice().unwrap(), b"hello secure world");
    }

    #[test]
    fn random_is_nonzero() {
        let buf = LockedBuffer::random(32).unwrap();
        assert_eq!(buf.len(), 32);
        assert!(buf.as_slice().unwrap().iter().any(|&b| b != 0));
    }

    #[test]
    fn freeze_melt_cycle() {
        let mut buf = LockedBuffer::new(16).unwrap();
        assert!(!buf.is_frozen());

        buf.freeze().unwrap();
        assert!(buf.is_frozen());
        assert!(buf.as_mut_slice().is_err());

        buf.melt().unwrap();
        buf.as_mut_slice().unwrap()[0] = 0xFF;
        assert_eq!(buf.as_slice().unwrap()[0], 0xFF);
    }

    #[test]
    fn wipe_zeros_data() {
        let mut buf = LockedBuffer::from_bytes(b"secret").unwrap();
        buf.melt().unwrap();
        buf.wipe().unwrap();
        assert!(buf.as_slice().unwrap().iter().all(|&b| b == 0));
    }

    #[test]
    fn scramble_changes_data() {
        let mut buf = LockedBuffer::new(64).unwrap();
        buf.scramble().unwrap();
        assert!(buf.as_slice().unwrap().iter().any(|&b| b != 0));
    }

    #[test]
    fn ct_eq_works() {
        let a = LockedBuffer::from_bytes(b"same").unwrap();
        let b = LockedBuffer::from_bytes(b"same").unwrap();
        let c = LockedBuffer::from_bytes(b"diff").unwrap();
        assert!(a.ct_eq(&b).unwrap());
        assert!(!a.ct_eq(&c).unwrap());
    }

    #[test]
    fn zero_size_is_error() {
        assert!(LockedBuffer::new(0).is_err());
    }

    #[test]
    fn destroyed_buffer_is_inaccessible() {
        let mut buf = LockedBuffer::new(32).unwrap();
        buf.destroy();
        assert!(buf.as_slice().is_err());
    }

    // ── Property-based tests (proptest) ──────────────────────
    // Skipped under Miri: `seal_open_roundtrip` runs ChaCha20-Poly1305 per case
    // and proptest fires 256 cases by default. The unit tests above already
    // exercise the same code paths at fixed inputs, which is what Miri needs.
    #[cfg(not(miri))]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn from_bytes_preserves_data(data in proptest::collection::vec(any::<u8>(), 1..512)) {
                let buf = LockedBuffer::from_bytes(&data).unwrap();
                prop_assert_eq!(buf.as_slice().unwrap(), &data[..]);
                prop_assert!(buf.is_frozen());
            }

            #[test]
            fn new_always_zeroed(size in 1usize..4096) {
                let buf = LockedBuffer::new(size).unwrap();
                let s = buf.as_slice().unwrap();
                prop_assert_eq!(s.len(), size);
                prop_assert!(s.iter().all(|&b| b == 0));
            }

            #[test]
            fn wipe_always_zeros(data in proptest::collection::vec(any::<u8>(), 1..512)) {
                let mut buf = LockedBuffer::from_bytes(&data).unwrap();
                buf.melt().unwrap();
                buf.wipe().unwrap();
                prop_assert!(buf.as_slice().unwrap().iter().all(|&b| b == 0));
            }

            #[test]
            fn seal_open_roundtrip(data in proptest::collection::vec(any::<u8>(), 1..256)) {
                let mut buf = LockedBuffer::new(data.len()).unwrap();
                buf.as_mut_slice().unwrap().copy_from_slice(&data);
                let enc = buf.seal().unwrap();
                let opened = enc.open().unwrap();
                prop_assert_eq!(opened.as_slice().unwrap(), &data[..]);
            }
        }
    }
}

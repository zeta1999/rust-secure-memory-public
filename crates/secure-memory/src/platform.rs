//! Platform abstraction for OS-level secure memory operations.
//!
//! Provides a unified API over Unix (mmap/mlock/mprotect) and
//! Windows (VirtualAlloc/VirtualLock/VirtualProtect).

use crate::error::Error;

// ── Public API ───────────────────────────────────────────────

/// Returns the system page size in bytes.
pub fn page_size() -> usize {
    sys::page_size()
}

/// Round `n` up to the next multiple of `align`.
#[inline]
pub fn round_up(n: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (n + align - 1) & !(align - 1)
}

/// Allocate `size` bytes of page-aligned memory (readable + writable).
///
/// # Safety
/// Caller must eventually free with [`free_mem`].
pub unsafe fn alloc_mem(size: usize) -> Result<*mut u8, Error> {
    sys::alloc_mem(size)
}

/// Free memory previously allocated with [`alloc_mem`].
///
/// # Safety
/// `ptr` must originate from `alloc_mem` with the matching `size`.
pub unsafe fn free_mem(ptr: *mut u8, size: usize) {
    sys::free_mem(ptr, size);
}

/// Lock memory into physical RAM, preventing swap-out.
///
/// # Safety
/// `ptr` must be valid and page-aligned; `len` must match the allocation.
pub unsafe fn lock(ptr: *mut u8, len: usize) -> Result<(), Error> {
    sys::lock(ptr, len)
}

/// Unlock previously locked memory.
///
/// # Safety
/// `ptr` must have been locked with [`lock`].
pub unsafe fn unlock(ptr: *mut u8, len: usize) {
    sys::unlock(ptr, len);
}

/// Set memory to no-access (guard page).
///
/// # Safety
/// `ptr` must be valid and page-aligned.
pub unsafe fn protect_none(ptr: *mut u8, len: usize) -> Result<(), Error> {
    sys::protect_none(ptr, len)
}

/// Set memory to read-only.
///
/// # Safety
/// `ptr` must be valid and page-aligned.
pub unsafe fn protect_read(ptr: *mut u8, len: usize) -> Result<(), Error> {
    sys::protect_read(ptr, len)
}

/// Set memory to read-write.
///
/// # Safety
/// `ptr` must be valid and page-aligned.
pub unsafe fn protect_rw(ptr: *mut u8, len: usize) -> Result<(), Error> {
    sys::protect_rw(ptr, len)
}

/// Advise the kernel to exclude this memory from core dumps.
///
/// # Safety
/// `ptr` must be valid.
pub unsafe fn dont_dump(ptr: *mut u8, len: usize) {
    sys::dont_dump(ptr, len);
}

// ── Unix implementation ──────────────────────────────────────

#[cfg(all(unix, not(miri)))]
mod sys {
    use crate::error::Error;

    pub fn page_size() -> usize {
        // SAFETY: sysconf(_SC_PAGESIZE) is always safe and returns > 0.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    pub unsafe fn alloc_mem(size: usize) -> Result<*mut u8, Error> {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(Error::AllocationFailed);
        }
        Ok(ptr as *mut u8)
    }

    pub unsafe fn free_mem(ptr: *mut u8, size: usize) {
        libc::munmap(ptr as *mut libc::c_void, size);
    }

    pub unsafe fn lock(ptr: *mut u8, len: usize) -> Result<(), Error> {
        if libc::mlock(ptr as *const libc::c_void, len) != 0 {
            return Err(Error::LockFailed);
        }
        Ok(())
    }

    pub unsafe fn unlock(ptr: *mut u8, len: usize) {
        libc::munlock(ptr as *const libc::c_void, len);
    }

    pub unsafe fn protect_none(ptr: *mut u8, len: usize) -> Result<(), Error> {
        if libc::mprotect(ptr as *mut libc::c_void, len, libc::PROT_NONE) != 0 {
            return Err(Error::ProtectFailed);
        }
        Ok(())
    }

    pub unsafe fn protect_read(ptr: *mut u8, len: usize) -> Result<(), Error> {
        if libc::mprotect(ptr as *mut libc::c_void, len, libc::PROT_READ) != 0 {
            return Err(Error::ProtectFailed);
        }
        Ok(())
    }

    pub unsafe fn protect_rw(ptr: *mut u8, len: usize) -> Result<(), Error> {
        if libc::mprotect(
            ptr as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
        {
            return Err(Error::ProtectFailed);
        }
        Ok(())
    }

    pub unsafe fn dont_dump(ptr: *mut u8, len: usize) {
        #[cfg(target_os = "linux")]
        {
            libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ptr, len);
        }
    }
}

// ── Windows implementation ───────────────────────────────────

#[cfg(all(windows, not(miri)))]
mod sys {
    use crate::error::Error;
    use windows_sys::Win32::System::Memory::*;
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    pub fn page_size() -> usize {
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        info.dwPageSize as usize
    }

    pub unsafe fn alloc_mem(size: usize) -> Result<*mut u8, Error> {
        let ptr = VirtualAlloc(
            std::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if ptr.is_null() {
            return Err(Error::AllocationFailed);
        }
        Ok(ptr as *mut u8)
    }

    pub unsafe fn free_mem(ptr: *mut u8, _size: usize) {
        VirtualFree(ptr as *mut _, 0, MEM_RELEASE);
    }

    pub unsafe fn lock(ptr: *mut u8, len: usize) -> Result<(), Error> {
        if VirtualLock(ptr as *mut _, len) == 0 {
            return Err(Error::LockFailed);
        }
        Ok(())
    }

    pub unsafe fn unlock(ptr: *mut u8, len: usize) {
        VirtualUnlock(ptr as *mut _, len);
    }

    pub unsafe fn protect_none(ptr: *mut u8, len: usize) -> Result<(), Error> {
        let mut old = 0u32;
        if VirtualProtect(ptr as *mut _, len, PAGE_NOACCESS, &mut old) == 0 {
            return Err(Error::ProtectFailed);
        }
        Ok(())
    }

    pub unsafe fn protect_read(ptr: *mut u8, len: usize) -> Result<(), Error> {
        let mut old = 0u32;
        if VirtualProtect(ptr as *mut _, len, PAGE_READONLY, &mut old) == 0 {
            return Err(Error::ProtectFailed);
        }
        Ok(())
    }

    pub unsafe fn protect_rw(ptr: *mut u8, len: usize) -> Result<(), Error> {
        let mut old = 0u32;
        if VirtualProtect(ptr as *mut _, len, PAGE_READWRITE, &mut old) == 0 {
            return Err(Error::ProtectFailed);
        }
        Ok(())
    }

    pub unsafe fn dont_dump(_ptr: *mut u8, _len: usize) {
        // No equivalent on Windows
    }
}

// ── Miri implementation ──────────────────────────────────────
//
// Under Miri, OS-level FFI like `mmap`/`mlock`/`mprotect` is unsupported. Use
// the global allocator and no-op the protection calls so Miri can still
// validate the algorithmic code (provenance, layout, drop order, AEAD/KEM
// logic). The OS-protection guarantees aren't something Miri can verify
// anyway — they're enforced by the kernel at runtime.

#[cfg(miri)]
mod sys {
    use crate::error::Error;
    use std::alloc::{alloc, dealloc, Layout};

    const PAGE_SIZE: usize = 4096;

    fn layout(size: usize) -> Layout {
        Layout::from_size_align(size, PAGE_SIZE).expect("page-aligned layout")
    }

    pub fn page_size() -> usize {
        PAGE_SIZE
    }

    pub unsafe fn alloc_mem(size: usize) -> Result<*mut u8, Error> {
        let ptr = alloc(layout(size));
        if ptr.is_null() {
            return Err(Error::AllocationFailed);
        }
        Ok(ptr)
    }

    pub unsafe fn free_mem(ptr: *mut u8, size: usize) {
        dealloc(ptr, layout(size));
    }

    pub unsafe fn lock(_ptr: *mut u8, _len: usize) -> Result<(), Error> {
        Ok(())
    }

    pub unsafe fn unlock(_ptr: *mut u8, _len: usize) {}

    pub unsafe fn protect_none(_ptr: *mut u8, _len: usize) -> Result<(), Error> {
        Ok(())
    }

    pub unsafe fn protect_read(_ptr: *mut u8, _len: usize) -> Result<(), Error> {
        Ok(())
    }

    pub unsafe fn protect_rw(_ptr: *mut u8, _len: usize) -> Result<(), Error> {
        Ok(())
    }

    pub unsafe fn dont_dump(_ptr: *mut u8, _len: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_size_is_power_of_two() {
        let ps = page_size();
        assert!(ps > 0);
        assert!(ps.is_power_of_two());
    }

    #[test]
    fn test_round_up() {
        assert_eq!(round_up(1, 4096), 4096);
        assert_eq!(round_up(4096, 4096), 4096);
        assert_eq!(round_up(4097, 4096), 8192);
        assert_eq!(round_up(0, 4096), 0);
    }

    #[test]
    fn test_alloc_and_free() {
        let ps = page_size();
        unsafe {
            let ptr = alloc_mem(ps).expect("alloc failed");
            assert!(!ptr.is_null());
            // Should be writable
            std::ptr::write_bytes(ptr, 0xAB, ps);
            free_mem(ptr, ps);
        }
    }
}

// ── Kani verification harnesses ──────────────────────────────

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// round_up never overflows for valid inputs and always returns ≥ n.
    #[kani::proof]
    fn round_up_no_overflow() {
        let n: usize = kani::any();
        let align: usize = kani::any();
        // Restrict to valid power-of-two alignments (1..=2^20)
        kani::assume(align > 0 && align.is_power_of_two() && align <= 1 << 20);
        kani::assume(n <= usize::MAX - align); // prevent wrapping
        let r = round_up(n, align);
        assert!(r >= n);
        assert!(r % align == 0);
    }

    /// round_up is idempotent: rounding an already-aligned value is a no-op.
    #[kani::proof]
    fn round_up_idempotent() {
        let align: usize = kani::any();
        kani::assume(align > 0 && align.is_power_of_two() && align <= 1 << 20);
        let n: usize = kani::any();
        kani::assume(n <= usize::MAX - align);
        let r = round_up(n, align);
        assert_eq!(round_up(r, align), r);
    }
}

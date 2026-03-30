#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_memory::LockedBuffer;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Cap at 64 KiB to avoid OOM
    let size = (data[0] as usize % 64) * 1024 + 1;
    let actual_size = size.min(data.len());

    if let Ok(mut buf) = LockedBuffer::new(actual_size) {
        // Write fuzzer data in
        let _ = buf.copy_from(&data[..actual_size]);

        // Freeze / melt cycle
        let _ = buf.freeze();
        assert!(buf.as_mut_slice().is_err()); // must be read-only
        let _ = buf.melt();

        // Scramble and wipe
        let _ = buf.scramble();
        let _ = buf.wipe();
        // After wipe, all bytes must be zero
        if let Ok(s) = buf.as_slice() {
            assert!(s.iter().all(|&b| b == 0));
        }
    }
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_memory::{Enclave, LockedBuffer};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Cap size
    let size = data.len().min(4096);
    let input = &data[..size];

    // Enclave roundtrip
    if let Ok(enc) = Enclave::new(input) {
        assert_eq!(enc.size(), size);
        let buf = enc.open().expect("open must succeed");
        assert_eq!(buf.as_slice().unwrap(), input);
    }

    // LockedBuffer → seal → open roundtrip
    if let Ok(mut buf) = LockedBuffer::new(size) {
        let _ = buf.as_mut_slice().map(|s| s[..size].copy_from_slice(input));
        if let Ok(enc) = buf.seal() {
            let opened = enc.open().expect("open must succeed");
            assert_eq!(opened.as_slice().unwrap(), input);
        }
    }
});

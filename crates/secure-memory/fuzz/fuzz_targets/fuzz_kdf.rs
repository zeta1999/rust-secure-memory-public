#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_memory::{derive_key_argon2, vdf_stretch};

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return; // need at least 1 byte password + 8 bytes salt
    }
    let (password, salt_and_rest) = data.split_at(data.len().min(64));
    let salt = if salt_and_rest.len() >= 8 {
        &salt_and_rest[..8]
    } else {
        return;
    };

    // Argon2 with minimum params to keep fuzzing fast
    if let Ok(key) = derive_key_argon2(password, salt, 256, 1) {
        assert_eq!(key.len(), 32);
        // Determinism: same inputs → same output
        let key2 = derive_key_argon2(password, salt, 256, 1).unwrap();
        assert_eq!(key, key2);
    }

    // VDF: always succeeds, always 32 bytes
    let hash = vdf_stretch(password, 2);
    assert_eq!(hash.len(), 32);
    let hash2 = vdf_stretch(password, 2);
    assert_eq!(hash, hash2);
});

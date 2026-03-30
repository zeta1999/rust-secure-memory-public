#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_memory::{encrypt, decrypt};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let (key, plaintext) = data.split_at(32);

    // Roundtrip: encrypt then decrypt must return the original
    if let Ok(ct) = encrypt(key, plaintext) {
        let pt = decrypt(key, &ct).expect("decrypt must succeed for valid ciphertext");
        assert_eq!(pt, plaintext);
    }

    // Wrong key must fail
    let mut wrong_key = [0u8; 32];
    wrong_key.copy_from_slice(key);
    wrong_key[0] ^= 0xFF;
    if let Ok(ct) = encrypt(key, plaintext) {
        assert!(decrypt(&wrong_key, &ct).is_err());
    }

    // Tampered ciphertext must fail
    if let Ok(mut ct) = encrypt(key, plaintext) {
        if !ct.is_empty() {
            let last = ct.len() - 1;
            ct[last] ^= 0xFF;
            assert!(decrypt(key, &ct).is_err());
        }
    }
});

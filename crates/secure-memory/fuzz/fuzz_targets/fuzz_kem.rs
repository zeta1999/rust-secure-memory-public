#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_memory::kem::{encapsulate, KemKeyPair, CT_SIZE, EK_SIZE};

fuzz_target!(|data: &[u8]| {
    // Fuzz encapsulate: wrong-sized keys must be rejected
    if data.len() != EK_SIZE {
        assert!(encapsulate(data).is_err());
    } else {
        // EK_SIZE bytes: may or may not be a valid public key
        let _ = encapsulate(data);
    }

    // Fuzz decapsulate: wrong-sized ciphertexts must be rejected;
    // CT_SIZE bytes trigger implicit rejection (different secret, no error)
    if let Ok(kp) = KemKeyPair::generate() {
        if data.len() != CT_SIZE {
            assert!(kp.decapsulate(data).is_err());
        } else {
            let _ = kp.decapsulate(data);
        }
    }
});

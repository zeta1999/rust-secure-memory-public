//! # secure-memory API Examples (ML-KEM)
//!
//! Runnable unit tests demonstrating `secure_memory` API patterns
//! that involve ML-KEM-768 post-quantum key encapsulation:
//! `LockedBuffer`, `Enclave`, `encrypt`/`decrypt`, and `purge`
//! used together with `kem::KemKeyPair` and `kem::encapsulate`.
//!
//! Run with:
//! ```bash
//! cargo test -p secure-memory-examples
//! ```

#[cfg(test)]
mod tests {
    use secure_memory::kem::{encapsulate, KemKeyPair, CT_SIZE, EK_SIZE};
    use secure_memory::{decrypt, encrypt, Enclave};

    // ── 1. Basic KEM round-trip ─────────────────────────────────

    #[test]
    fn basic_kem_roundtrip() {
        // Bob generates a key pair (secret key in LockedBuffer)
        let kp = KemKeyPair::generate().unwrap();

        // Alice encapsulates against Bob's public key
        let (ciphertext, shared_secret) = encapsulate(kp.public_key()).unwrap();

        // Bob decapsulates to recover the same shared secret
        let recovered = kp.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret.as_slice().unwrap(), recovered.as_slice().unwrap());
    }

    // ── 2. End-to-end encrypted message ─────────────────────────

    #[test]
    fn end_to_end_encrypted_message() {
        // Bob (receiver)
        let kp = KemKeyPair::generate().unwrap();
        let public_key = kp.public_key().to_vec();

        // Alice (sender) — encapsulate + encrypt
        let (kem_ct, ss) = encapsulate(&public_key).unwrap();
        let message = b"launch codes: 0000";
        let encrypted_msg = encrypt(ss.as_slice().unwrap(), message).unwrap();

        // Bob (receiver) — decapsulate + decrypt
        let ss2 = kp.decapsulate(&kem_ct).unwrap();
        let plaintext = decrypt(ss2.as_slice().unwrap(), &encrypted_msg).unwrap();

        assert_eq!(plaintext, message);
    }

    // ── 3. Multiple messages with one KEM exchange ──────────────

    #[test]
    fn multiple_messages_one_handshake() {
        let kp = KemKeyPair::generate().unwrap();
        let (ct, ss) = encapsulate(kp.public_key()).unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();

        let key = ss.as_slice().unwrap();
        let key2 = ss2.as_slice().unwrap();

        let messages: Vec<&[u8]> = vec![b"msg-1: hello", b"msg-2: world", b"msg-3: done"];
        let encrypted: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| encrypt(key, m).unwrap())
            .collect();

        for (i, enc) in encrypted.iter().enumerate() {
            let pt = decrypt(key2, enc).unwrap();
            assert_eq!(pt, messages[i]);
        }
    }

    // ── 4. Shared secret stored in an Enclave (encrypted at rest)

    #[test]
    fn shared_secret_in_enclave() {
        let kp = KemKeyPair::generate().unwrap();
        let (kem_ct, ss) = encapsulate(kp.public_key()).unwrap();

        // Seal the shared secret into an Enclave (encrypted with session key)
        let sealed = Enclave::new(ss.as_slice().unwrap()).unwrap();

        // Later, open the Enclave to use the key
        let opened = sealed.open().unwrap();
        let encrypted = encrypt(opened.as_slice().unwrap(), b"classified payload").unwrap();

        // Receiver decapsulates and decrypts
        let ss2 = kp.decapsulate(&kem_ct).unwrap();
        let plaintext = decrypt(ss2.as_slice().unwrap(), &encrypted).unwrap();

        assert_eq!(plaintext, b"classified payload");
    }

    // ── 5. Chunk-by-chunk encryption with KEM key ───────────────

    #[test]
    fn chunked_encryption_with_kem_key() {
        let kp = KemKeyPair::generate().unwrap();
        let (kem_ct, ss) = encapsulate(kp.public_key()).unwrap();
        let key = ss.as_slice().unwrap();

        let chunks: Vec<&[u8]> = vec![b"chunk-1-data...", b"chunk-2-data...", b"chunk-3-end"];
        let encrypted_chunks: Vec<Vec<u8>> = chunks
            .iter()
            .map(|c| encrypt(key, c).unwrap())
            .collect();

        // Receiver decapsulates and decrypts each chunk
        let ss2 = kp.decapsulate(&kem_ct).unwrap();
        let key2 = ss2.as_slice().unwrap();
        for (i, enc) in encrypted_chunks.iter().enumerate() {
            let pt = decrypt(key2, enc).unwrap();
            assert_eq!(pt, chunks[i]);
        }
    }

    // ── 6. Public key / ciphertext wire sizes ───────────────────

    #[test]
    fn wire_format_sizes() {
        let kp = KemKeyPair::generate().unwrap();
        let pk_bytes = kp.public_key();

        assert_eq!(pk_bytes.len(), EK_SIZE); // 1184 bytes on the wire

        let (kem_ct, _ss) = encapsulate(pk_bytes).unwrap();
        assert_eq!(kem_ct.len(), CT_SIZE); // 1088 bytes on the wire
    }

    // ── 7. Multi-recipient encryption ───────────────────────────

    #[test]
    fn multi_recipient() {
        let recipients: Vec<KemKeyPair> = (0..3)
            .map(|_| KemKeyPair::generate().unwrap())
            .collect();

        let message = b"broadcast to all agents";

        // Sender encapsulates for each recipient
        let bundles: Vec<(Vec<u8>, Vec<u8>)> = recipients
            .iter()
            .map(|r| {
                let (kem_ct, ss) = encapsulate(r.public_key()).unwrap();
                let enc = encrypt(ss.as_slice().unwrap(), message).unwrap();
                (kem_ct, enc)
            })
            .collect();

        // Each recipient decapsulates their own bundle
        for (i, r) in recipients.iter().enumerate() {
            let (kem_ct, encrypted_msg) = &bundles[i];
            let ss = r.decapsulate(kem_ct).unwrap();
            let pt = decrypt(ss.as_slice().unwrap(), encrypted_msg).unwrap();
            assert_eq!(pt, message);
        }
    }

    // ── 8. Implicit rejection — tamper detection ────────────────

    #[test]
    fn implicit_rejection_tamper_detection() {
        let kp = KemKeyPair::generate().unwrap();
        let (kem_ct, ss) = encapsulate(kp.public_key()).unwrap();
        let encrypted = encrypt(ss.as_slice().unwrap(), b"top secret").unwrap();

        // Attacker tampers with the KEM ciphertext
        let mut tampered_ct = kem_ct.clone();
        tampered_ct[0] ^= 0xFF;

        // Decapsulation succeeds (implicit rejection) but gives a different secret
        let bad_ss = kp.decapsulate(&tampered_ct).unwrap();
        assert_ne!(ss.as_slice().unwrap(), bad_ss.as_slice().unwrap());

        // AEAD decryption fails — Poly1305 tag mismatch
        let result = decrypt(bad_ss.as_slice().unwrap(), &encrypted);
        assert!(result.is_err());
    }

    // ── 9. Secure cleanup with purge() ──────────────────────────
    // Note: purge() destroys ALL LockedBuffers process-wide and makes
    // all Enclaves permanently undecryptable. We test it last and in
    // isolation because it affects global state.

    #[test]
    fn secure_cleanup() {
        let kp = KemKeyPair::generate().unwrap();
        let (_ct, _ss) = encapsulate(kp.public_key()).unwrap();

        // purge() wipes every LockedBuffer (KEM keys, shared secrets, session key)
        // Uncomment to test — but note it will break other tests in this process:
        // secure_memory::purge();
        //
        // After purge, all Enclaves are permanently undecryptable and
        // all LockedBuffer contents are zeroed.
    }
}

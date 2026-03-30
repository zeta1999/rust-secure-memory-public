//! Integration test: encrypt → save → load → decrypt round-trip (v2 format with per-file salt).

#[test]
fn encrypted_file_roundtrip_v2() {
    let dir = std::env::temp_dir().join("sedit-test-v2");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.enc");

    // Simulate: password → derive key with random salt → encrypt → save → load → decrypt
    let password = secure_memory::LockedBuffer::from_bytes(b"test-passphrase-123").unwrap();

    let salt: [u8; 16] = {
        let mut s = [0u8; 16];
        secure_memory::scramble_bytes(&mut s);
        s
    };

    let mut key_bytes =
        secure_memory::derive_key_combined(password.as_slice().unwrap(), &salt, 1024, 1, 10)
            .unwrap();
    let key = secure_memory::LockedBuffer::from_bytes_move(&mut key_bytes).unwrap();

    // Save v2 format: magic + salt + encrypted
    let original = "Hello, encrypted world!\nLine 2.\n";
    let ct = secure_memory::encrypt(key.as_slice().unwrap(), original.as_bytes()).unwrap();
    let magic_v2 = b"SEDIT\x00\x02\x00";
    let mut file_data = Vec::new();
    file_data.extend_from_slice(magic_v2);
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&ct);
    std::fs::write(&path, &file_data).unwrap();

    // Verify header
    let loaded = std::fs::read(&path).unwrap();
    assert_eq!(&loaded[..8], magic_v2);

    // Extract salt and decrypt
    let loaded_salt = &loaded[8..24];
    assert_eq!(loaded_salt, &salt);

    let decrypted = secure_memory::decrypt(key.as_slice().unwrap(), &loaded[24..]).unwrap();
    assert_eq!(String::from_utf8(decrypted).unwrap(), original);

    std::fs::remove_file(&path).unwrap();
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn wrong_key_fails_to_decrypt() {
    let dir = std::env::temp_dir().join("sedit-test-wrong-key");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test2.enc");

    let salt = b"fixed-test-salt!";

    let mut k1 = secure_memory::derive_key_combined(b"correct", salt, 1024, 1, 10).unwrap();
    let key1 = secure_memory::LockedBuffer::from_bytes_move(&mut k1).unwrap();

    let mut k2 = secure_memory::derive_key_combined(b"wrong", salt, 1024, 1, 10).unwrap();
    let key2 = secure_memory::LockedBuffer::from_bytes_move(&mut k2).unwrap();

    // Encrypt with key1 (v2 format)
    let ct = secure_memory::encrypt(key1.as_slice().unwrap(), b"secret data").unwrap();
    let magic_v2 = b"SEDIT\x00\x02\x00";
    let mut file_data = Vec::new();
    file_data.extend_from_slice(magic_v2);
    file_data.extend_from_slice(salt);
    file_data.extend_from_slice(&ct);
    std::fs::write(&path, &file_data).unwrap();

    // Decrypt with key2 must fail
    let loaded = std::fs::read(&path).unwrap();
    let result = secure_memory::decrypt(key2.as_slice().unwrap(), &loaded[24..]);
    assert!(result.is_err());

    std::fs::remove_file(&path).unwrap();
    let _ = std::fs::remove_dir(&dir);
}

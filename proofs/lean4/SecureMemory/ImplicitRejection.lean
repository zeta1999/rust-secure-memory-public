import SecureMemory.Primitives

/-!
# Implicit Rejection Analysis

Proves that ML-KEM-768's implicit rejection property, combined with
KDF injectivity and AEAD authenticity, ensures that a tampered KEM
ciphertext always leads to AEAD authentication failure.

This is the formal argument for why the system is safe against
chosen-ciphertext attacks even without explicit KEM error signaling.
-/

-- ══════════════════════════════════════════════════════════════
-- Theorems
-- ══════════════════════════════════════════════════════════════

/-- **Tampered CT → different shared secret**: if an attacker modifies
    the KEM ciphertext, decapsulation yields a different shared secret
    (ML-KEM implicit rejection, FIPS 203 §5.2). -/
theorem tampered_ct_different_secret (sk : SecretKey)
    (ct_real ct_tampered : KEMCiphertext) (h : ct_real ≠ ct_tampered) :
    kemDecapsulate sk ct_real ≠ kemDecapsulate sk ct_tampered :=
  kem_implicit_rejection sk ct_real ct_tampered h

/-- **Different shared secret → different AEAD key**: KDF injectivity
    ensures distinct shared secrets produce distinct symmetric keys. -/
theorem different_secret_different_key (ss ss' : SharedSecret) (h : ss ≠ ss') :
    kdf ss ≠ kdf ss' :=
  kdf_injective ss ss' h

/-- **Wrong AEAD key → decryption fails**: AEAD authenticity ensures
    that decrypting with a mismatched key returns `none`. -/
theorem wrong_key_decryption_fails (k k' : AeadKey) (n : Nonce)
    (pt : Plaintext) (h : k ≠ k') :
    aeadDecrypt k' n (aeadEncrypt k n pt) = none :=
  aead_key_mismatch k k' n pt h

/-- **Implicit rejection → AEAD authentication failure** (main theorem):
    If an attacker tampers with a KEM ciphertext, the receiver derives
    a different AEAD key, and AEAD decryption fails with authentication
    error. The attacker learns nothing about the plaintext.

    Chain: ct ≠ ct' → ss ≠ ss' → kdf(ss) ≠ kdf(ss') → decrypt fails -/
theorem implicit_rejection_aead_fails
    (kp : KeyPair) (n : Nonce) (pt : Plaintext)
    (ct_tampered : KEMCiphertext)
    (h_tamper : (kemEncapsulate kp.pk).1 ≠ ct_tampered) :
    aeadDecrypt (kdf (kemDecapsulate kp.sk ct_tampered)) n
      (aeadEncrypt (kdf (kemEncapsulate kp.pk).2) n pt) = none := by
  -- Step 1: kem_correctness gives us kemDecapsulate kp.sk ct_real = ss_real
  have h_kem := kem_correctness kp
  -- Step 2: implicit rejection — distinct CTs decapsulate to distinct secrets
  have h_ss_ne : kemDecapsulate kp.sk (kemEncapsulate kp.pk).1 ≠
                 kemDecapsulate kp.sk ct_tampered :=
    kem_implicit_rejection kp.sk (kemEncapsulate kp.pk).1 ct_tampered h_tamper
  -- By kem_correctness, kemDecapsulate kp.sk ct_real = ss_real
  -- so (kemEncapsulate kp.pk).2 ≠ kemDecapsulate kp.sk ct_tampered
  rw [h_kem] at h_ss_ne
  -- Step 3: KDF injectivity — different secrets → different keys
  have h_key_ne := kdf_injective _ _ h_ss_ne
  -- Step 4: wrong key → AEAD authentication failure
  exact aead_key_mismatch _ _ n pt h_key_ne

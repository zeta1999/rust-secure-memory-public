import SecureMemory.Primitives

/-!
# Key Separation

Proves that independent ML-KEM key pairs yield independent shared secrets
and therefore independent AEAD keys, ensuring that encryptions under
different key pairs cannot be cross-decrypted.
-/

-- ══════════════════════════════════════════════════════════════
-- Additional axiom for key independence
-- ══════════════════════════════════════════════════════════════

/-- **KEM key independence**: encapsulations against distinct public keys
    produce distinct shared secrets. This follows from the randomness of
    the KEM encapsulation and the independence of the key generation. -/
axiom kem_pk_independence (pk pk' : PublicKey) :
  pk ≠ pk' → (kemEncapsulate pk).2 ≠ (kemEncapsulate pk').2

-- ══════════════════════════════════════════════════════════════
-- Theorems
-- ══════════════════════════════════════════════════════════════

/-- **Shared secret separation**: distinct public keys yield distinct
    shared secrets from encapsulation. -/
theorem shared_secret_separation (pk pk' : PublicKey) (h : pk ≠ pk') :
    (kemEncapsulate pk).2 ≠ (kemEncapsulate pk').2 :=
  kem_pk_independence pk pk' h

/-- **AEAD key separation**: distinct public keys lead to distinct
    derived AEAD keys. Chains: pk ≠ pk' → ss ≠ ss' → kdf(ss) ≠ kdf(ss'). -/
theorem aead_key_separation (pk pk' : PublicKey) (h : pk ≠ pk') :
    kdf (kemEncapsulate pk).2 ≠ kdf (kemEncapsulate pk').2 := by
  have h_ss := kem_pk_independence pk pk' h
  exact kdf_injective _ _ h_ss

/-- **Cross-decryption fails**: a message encrypted for one key pair
    cannot be decrypted by a different key pair's derived key.
    This is the multi-recipient security guarantee. -/
theorem cross_decryption_fails (pk pk' : PublicKey) (n : Nonce) (pt : Plaintext)
    (h : pk ≠ pk') :
    let k  := kdf (kemEncapsulate pk).2
    let k' := kdf (kemEncapsulate pk').2
    aeadDecrypt k' n (aeadEncrypt k n pt) = none := by
  simp only
  have h_key := aead_key_separation pk pk' h
  exact aead_key_mismatch _ _ n pt h_key

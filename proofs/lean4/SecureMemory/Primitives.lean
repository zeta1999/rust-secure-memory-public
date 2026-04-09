/-!
# Cryptographic Primitives — Types and Axioms

Abstract model of ML-KEM-768 (FIPS 203), XChaCha20-Poly1305, and Argon2id+VDF KDF.
We do NOT prove the primitives correct — we **assume** their documented properties
and use them to prove high-level composition theorems.
-/

-- ══════════════════════════════════════════════════════════════
-- Types
-- ══════════════════════════════════════════════════════════════

/-- ML-KEM-768 public (encapsulation) key — 1184 bytes. -/
axiom PublicKey : Type
/-- ML-KEM-768 secret (decapsulation) key — 2400 bytes. -/
axiom SecretKey : Type

/-- ML-KEM-768 key pair. -/
structure KeyPair where
  pk : PublicKey
  sk : SecretKey

/-- ML-KEM-768 ciphertext — 1088 bytes. -/
axiom KEMCiphertext : Type
/-- 32-byte shared secret produced by KEM encapsulation/decapsulation. -/
axiom SharedSecret : Type
/-- 32-byte symmetric key for AEAD. -/
axiom AeadKey : Type
/-- 24-byte nonce for XChaCha20-Poly1305. -/
axiom Nonce : Type
/-- Arbitrary-length plaintext. -/
axiom Plaintext : Type
/-- AEAD ciphertext (nonce || encrypted data || Poly1305 tag). -/
axiom AeadCiphertext : Type

-- DecidableEq instances needed for ≠ reasoning
noncomputable instance : DecidableEq PublicKey := Classical.typeDecidableEq _
noncomputable instance : DecidableEq SecretKey := Classical.typeDecidableEq _
noncomputable instance : DecidableEq KEMCiphertext := Classical.typeDecidableEq _
noncomputable instance : DecidableEq SharedSecret := Classical.typeDecidableEq _
noncomputable instance : DecidableEq AeadKey := Classical.typeDecidableEq _
noncomputable instance : DecidableEq Nonce := Classical.typeDecidableEq _
noncomputable instance : DecidableEq Plaintext := Classical.typeDecidableEq _
noncomputable instance : DecidableEq AeadCiphertext := Classical.typeDecidableEq _

-- ══════════════════════════════════════════════════════════════
-- Primitive operations
-- ══════════════════════════════════════════════════════════════

/-- Encapsulate against a public key, producing (ciphertext, shared_secret). -/
axiom kemEncapsulate (pk : PublicKey) : KEMCiphertext × SharedSecret

/-- Decapsulate a ciphertext using the secret key, recovering the shared secret. -/
axiom kemDecapsulate (sk : SecretKey) (ct : KEMCiphertext) : SharedSecret

/-- XChaCha20-Poly1305 authenticated encryption. -/
axiom aeadEncrypt (k : AeadKey) (n : Nonce) (pt : Plaintext) : AeadCiphertext

/-- XChaCha20-Poly1305 authenticated decryption (returns `none` on auth failure). -/
axiom aeadDecrypt (k : AeadKey) (n : Nonce) (ct : AeadCiphertext) : Option Plaintext

/-- Key derivation function: SharedSecret → AeadKey (Argon2id + VDF). -/
axiom kdf (ss : SharedSecret) : AeadKey

-- ══════════════════════════════════════════════════════════════
-- Axioms — assumed properties of the primitives
-- ══════════════════════════════════════════════════════════════

-- ML-KEM-768 (FIPS 203) ──────────────────────────────────────

/-- **KEM correctness**: decapsulating a legitimately encapsulated ciphertext
    recovers the same shared secret the encapsulator obtained. -/
axiom kem_correctness (kp : KeyPair) :
  let (ct, ss) := kemEncapsulate kp.pk
  kemDecapsulate kp.sk ct = ss

/-- **Implicit rejection**: two distinct ciphertexts decapsulate to distinct
    shared secrets under the same secret key. (FIPS 203 §5.2) -/
axiom kem_implicit_rejection (sk : SecretKey) (ct ct' : KEMCiphertext) :
  ct ≠ ct' → kemDecapsulate sk ct ≠ kemDecapsulate sk ct'

-- XChaCha20-Poly1305 (RFC 8439 / extended nonce) ─────────────

/-- **AEAD correctness**: decrypting a legitimately produced ciphertext
    recovers the original plaintext. -/
axiom aead_correctness (k : AeadKey) (n : Nonce) (pt : Plaintext) :
  aeadDecrypt k n (aeadEncrypt k n pt) = some pt

/-- **AEAD authenticity**: decrypting with a different key always fails. -/
axiom aead_key_mismatch (k k' : AeadKey) (n : Nonce) (pt : Plaintext) :
  k ≠ k' → aeadDecrypt k' n (aeadEncrypt k n pt) = none

-- KDF (Argon2id + VDF) ───────────────────────────────────────

/-- **KDF determinism**: the same shared secret always derives the same key. -/
axiom kdf_deterministic (ss : SharedSecret) : kdf ss = kdf ss

/-- **KDF injectivity**: distinct shared secrets produce distinct AEAD keys. -/
axiom kdf_injective (ss ss' : SharedSecret) : ss ≠ ss' → kdf ss ≠ kdf ss'

-- Security properties (opaque propositions) ──────────────────

/-- ML-KEM-768 is IND-CCA2 secure. -/
axiom KemIndCca2 : Prop
/-- XChaCha20-Poly1305 is IND-CPA secure. -/
axiom AeadIndCpa : Prop
/-- XChaCha20-Poly1305 has ciphertext integrity (INT-CTXT). -/
axiom AeadIntCtxt : Prop

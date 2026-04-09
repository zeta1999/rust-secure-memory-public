import SecureMemory.Primitives
import SecureMemory.Buffer
import SecureMemory.Composition
import SecureMemory.ImplicitRejection
import SecureMemory.KeySeparation

/-!
# Secure Memory — Formal Verification Summary

Lean4 proofs for the high-level security properties of the
ML-KEM-768 + XChaCha20-Poly1305 composition used in `rust-secure-memory`.

## Approach

We model the cryptographic primitives as opaque functions with
**axiomatised** properties (correctness, IND-CCA2, INT-CTXT, etc.).
We then **prove** that the composition of these primitives satisfies
high-level security goals. This is the standard "game-based" approach
to cryptographic protocol verification.

## Axioms (assumed — properties of the primitives)

| Axiom                  | Source         | Property                                      |
|------------------------|----------------|-----------------------------------------------|
| `kem_correctness`      | FIPS 203       | Encaps/decaps roundtrip                       |
| `kem_implicit_rejection` | FIPS 203 §5.2 | Distinct CTs → distinct shared secrets        |
| `KemIndCca2`           | FIPS 203       | ML-KEM-768 is IND-CCA2                        |
| `aead_correctness`     | RFC 8439       | Encrypt/decrypt roundtrip                     |
| `aead_key_mismatch`    | RFC 8439       | Wrong-key decrypt fails                       |
| `AeadIndCpa`           | RFC 8439       | XChaCha20-Poly1305 is IND-CPA                 |
| `AeadIntCtxt`          | RFC 8439       | XChaCha20-Poly1305 has INT-CTXT               |
| `kdf_deterministic`    | Argon2 spec    | Same input → same key                         |
| `kdf_injective`        | Argon2 spec    | Distinct inputs → distinct keys               |
| `kem_pk_independence`  | FIPS 203       | Distinct PKs → independent shared secrets     |

## Proved Theorems

### Composition (`Composition.lean`)
1. `kem_roundtrip` — KEM encaps/decaps recovers shared secret
2. `aead_roundtrip` — AEAD encrypt/decrypt recovers plaintext
3. **`kem_aead_roundtrip`** — Composed scheme correctly roundtrips
4. **`kem_aead_ind_cca2`** — Composed scheme is IND-CCA2 (from axioms)

### Implicit Rejection (`ImplicitRejection.lean`)
5. `tampered_ct_different_secret` — Tampered KEM CT → different shared secret
6. `different_secret_different_key` — Different SS → different AEAD key
7. `wrong_key_decryption_fails` — Wrong AEAD key → auth failure
8. **`implicit_rejection_aead_fails`** — Full chain: tampered CT → AEAD auth failure

### Key Separation (`KeySeparation.lean`)
9. `shared_secret_separation` — Distinct PKs → distinct shared secrets
10. `aead_key_separation` — Distinct PKs → distinct AEAD keys
11. **`cross_decryption_fails`** — Message for PK₁ cannot be decrypted with PK₂'s key

### Buffer Safety (`Buffer.lean`)
12. `wipe_produces_zeros` — Wipe zeroes all data
13. `destroyed_inaccessible` — Destroyed buffer returns `none`
14. `frozen_denies_mutation` — Frozen buffer denies mutable access
15. `freeze_melt_roundtrip` — Melt restores mutability
16. **`purge_completeness`** — All purged buffers are inaccessible
17. **`purge_zeroes_all`** — All purged buffers have zeroed data
18. **`secret_confinement`** — No non-zero secret survives purge
-/

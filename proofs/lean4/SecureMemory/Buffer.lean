import SecureMemory.Primitives

/-!
# LockedBuffer — Abstract Memory Model

Models the secure memory invariants of `LockedBuffer` in Rust:
guard pages, mlock, canary sentinels, freeze/melt, secure wipe.

We prove properties about the *logical* state transitions, not
the OS-level implementations.
-/

-- ══════════════════════════════════════════════════════════════
-- LockedBuffer model
-- ══════════════════════════════════════════════════════════════

/-- Abstract model of a LockedBuffer. -/
structure LockedBuffer where
  data   : List UInt8
  alive  : Bool
  frozen : Bool
  deriving Repr, BEq

/-- A buffer satisfies the locked invariant when it is alive. -/
def isLockedInvariant (lb : LockedBuffer) : Prop :=
  lb.alive = true

-- ══════════════════════════════════════════════════════════════
-- Operations
-- ══════════════════════════════════════════════════════════════

/-- Read access: returns data only if the buffer is alive. -/
def asSlice (lb : LockedBuffer) : Option (List UInt8) :=
  if lb.alive then some lb.data else none

/-- Mutable access: returns data only if alive AND not frozen. -/
def asMutSlice (lb : LockedBuffer) : Option (List UInt8) :=
  if lb.alive && !lb.frozen then some lb.data else none

/-- Freeze: make the buffer read-only (models mprotect PROT_READ). -/
def freeze (lb : LockedBuffer) : LockedBuffer :=
  { lb with frozen := true }

/-- Melt: restore write access (models mprotect PROT_READ|PROT_WRITE). -/
def melt (lb : LockedBuffer) : LockedBuffer :=
  { lb with frozen := false }

/-- Wipe: securely zero all data (models zeroize on drop). -/
def wipe (lb : LockedBuffer) : LockedBuffer :=
  { lb with data := List.replicate lb.data.length 0 }

/-- Destroy: mark the buffer as no longer accessible. -/
def destroy (lb : LockedBuffer) : LockedBuffer :=
  { (wipe lb) with alive := false }

/-- Purge: wipe and destroy all buffers in a list. -/
def purge (buffers : List LockedBuffer) : List LockedBuffer :=
  buffers.map destroy

-- ══════════════════════════════════════════════════════════════
-- Theorems
-- ══════════════════════════════════════════════════════════════

/-- **Wipe produces zeros**: after wiping, every byte is 0. -/
theorem wipe_produces_zeros (lb : LockedBuffer) :
    (wipe lb).data = List.replicate lb.data.length 0 := by
  simp [wipe]

/-- **Wipe preserves aliveness**: wiping does not destroy the buffer. -/
theorem wipe_preserves_alive (lb : LockedBuffer) :
    (wipe lb).alive = lb.alive := by
  simp [wipe]

/-- **Destroyed buffer is inaccessible**: asSlice returns none. -/
theorem destroyed_inaccessible (lb : LockedBuffer) :
    asSlice (destroy lb) = none := by
  simp [asSlice, destroy, wipe]

/-- **Destroyed buffer has zeroed data**: data is all zeros. -/
theorem destroyed_data_zeroed (lb : LockedBuffer) :
    (destroy lb).data = List.replicate lb.data.length 0 := by
  simp [destroy, wipe]

/-- **Frozen buffer denies mutation**: asMutSlice returns none. -/
theorem frozen_denies_mutation (lb : LockedBuffer) (_h : lb.alive = true) :
    asMutSlice (freeze lb) = none := by
  simp [asMutSlice, freeze]

/-- **Freeze-melt roundtrip**: melting a frozen buffer restores mutability. -/
theorem freeze_melt_roundtrip (lb : LockedBuffer) (h : lb.alive = true) :
    asMutSlice (melt (freeze lb)) = some lb.data := by
  simp [asMutSlice, melt, freeze, h]

/-- **Purge completeness**: every buffer in `purge bs` is inaccessible. -/
theorem purge_completeness (bs : List LockedBuffer) :
    ∀ lb ∈ purge bs, asSlice lb = none := by
  intro lb h_mem
  simp [purge] at h_mem
  obtain ⟨b, _, h_eq⟩ := h_mem
  rw [← h_eq]
  exact destroyed_inaccessible b

/-- **Purge zeroes all data**: every buffer in `purge bs` has all-zero data. -/
theorem purge_zeroes_all (bs : List LockedBuffer) :
    ∀ lb ∈ purge bs, lb.data = List.replicate lb.data.length 0 := by
  intro lb h_mem
  simp [purge] at h_mem
  obtain ⟨b, _, h_eq⟩ := h_mem
  rw [← h_eq]
  simp [destroy, wipe]

/-- **Secret confinement**: after purge, no original data is recoverable.
    For any byte sequence `secret` that was stored in a buffer before purge,
    the purged buffer does not contain `secret` (unless secret is all zeros). -/
theorem secret_confinement (bs : List LockedBuffer) (secret : List UInt8)
    (h_nonzero : secret ≠ List.replicate secret.length 0) :
    ∀ lb ∈ purge bs, lb.data ≠ secret := by
  intro lb h_mem h_eq
  have h_zeroed := purge_zeroes_all bs lb h_mem
  rw [h_eq] at h_zeroed
  exact h_nonzero h_zeroed

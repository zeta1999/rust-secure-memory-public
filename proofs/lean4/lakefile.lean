import Lake
open Lake DSL

package «secure-memory-proofs» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib SecureMemory where
  srcDir := "."
  roots := #[
    `SecureMemory.Primitives,
    `SecureMemory.Buffer,
    `SecureMemory.Composition,
    `SecureMemory.ImplicitRejection,
    `SecureMemory.KeySeparation,
    `SecureMemory.Main
  ]

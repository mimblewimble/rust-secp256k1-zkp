# Changelog

## 0.8.0 (Unreleased)

This release updates `grin_secp256k1zkp` with fixes to buffer initialization,
Bulletproof generator initialization, C return-value handling, and scratch-space
cleanup. It includes breaking Rust API changes described below. These notes cover
changes since `v0.7.15`.

### Breaking changes

- `Secp256k1::bullet_proof` and `Secp256k1::range_proof` now return
  `Result<RangeProof, Error>`. Callers must handle proof-generation failures.
- `Secp256k1::rewind_range_proof` now returns `Result<ProofInfo, Error>`.
  Invalid commitments return an error instead of causing an unwrap panic.
  After obtaining `ProofInfo`, callers must still check `success`: a failed
  Borromean rewind can return `Ok(ProofInfo { success: false, .. })`.
- Legacy Borromean APIs require the new, opt-in `borromean` feature:
  `range_proof`, `verify_range_proof`, `rewind_range_proof`, `range_proof_info`,
  and `constants::PROOF_MSG_SIZE`. The Borromean message size is 2048 bytes
  whenever this feature is enabled. Bulletproof APIs remain available by default.
- Error variants are more specific. `PartialSigFailure` and
  `SigSubtractionFailure` have been removed; update matches using the migration
  table below. New variants also require changes to exhaustive `Error` matches.
- Uninitialized `blank()` constructors have been removed from
  `ffi::PublicKey`, `ffi::Signature`, `ffi::RecoverableSignature`,
  `ffi::AggSigPartialSignature`, and `ffi::SharedSecret`. Use their zeroed
  `new()` constructors. `pedersen::CommitmentInternal::blank()` is also replaced
  by `new()`.
- Raw FFI signatures have changed: output buffers use mutable pointers,
  read-only context parameters use const pointers, public-key combination counts
  use `size_t`, the aggregate verification `is_partial` flag uses `c_int`, and
  range-proof verification bounds use raw mutable pointers. `NonceFn` now takes
  `data: *mut c_void` before `attempt: c_uint`.
- The opaque FFI types `Context`, `AggSigContext`, `ScratchSpace`, and
  `BulletproofGenerators` no longer implement `Clone`. The safe Rust
  `Secp256k1` wrapper retains its `Clone` implementation.

### Fixes

- Replace uninitialized arrays and FFI objects with zeroed buffers in key,
  signature, shared-secret, commitment, and proof operations.
- Initialize shared Bulletproof generators once using synchronized publication,
  removing the race on the shared mutable generator pointer.
- Check C return values when creating and serializing commitments, creating
  proofs, and performing aggregate-signature operations. Failed proof creation
  no longer returns a `RangeProof` as though it succeeded.
- Return a deserialization error for range proofs longer than `MAX_PROOF_SIZE`
  instead of indexing past the proof buffer.
- Check scratch-space allocation before batch signature verification and
  Bulletproof operations, and check context and generator allocations for null.
- Update the bundled `secp256k1-zkp` C library to commit
  `0eefcedc1fec37d54e53bac4e535afa47d6774fa`, which fixes scratch-space cleanup
  in Bulletproof verification.
- Remove the unconditional `-g` flag from the C build.

### Tests

Add regression coverage for invalid commitments, oversized proof
deserialization, tampered and truncated Bulletproofs, wrong commitments and
rewind nonces, mismatched aggregate-signature nonces, and commitment balance
checks in a simulated transaction. Update test timing calls to use Chrono's
`timestamp_nanos_opt()`.

### Upgrading from 0.7.15

Update the dependency version while retaining any features your application needs:

```toml
[dependencies]
grin_secp256k1zkp = "0.8.0"
```

For applications using legacy Borromean proofs, enable the feature explicitly:

```toml
[dependencies]
grin_secp256k1zkp = { version = "0.8.0", features = ["borromean"] }
```

Propagate or handle errors from `bullet_proof`, `range_proof`, and
`rewind_range_proof` before using their results. Review error matches by operation:

| Operation | Previous failure variant | New failure variant |
| --- | --- | --- |
| Export a secret nonce | `InvalidSignature` | `CannotExportNonce` |
| Create a single signature | `InvalidSignature` | `CannotCreateSignature` |
| Add single signatures | `InvalidSignature` | `CannotCombineSignatures` |
| Create a partial signature | `PartialSigFailure` | `CannotCreatePartialSignature` |
| Combine partial signatures | `PartialSigFailure` | `CannotCombineSignatures` |
| Subtract a signature with no quadratic-residue solution | `SigSubtractionFailure` | `SignatureNoQuadraticResidue` |
| Other signature subtraction failures | `InvalidSignature` | `CannotSubtractSignature` |
| Verify a Bulletproof | `InvalidRangeProof` | `InvalidBulletproof` |
| Rewind a Bulletproof | `InvalidRangeProof` | `CannotRewindBulletproof` |

Proof-generation failures now use `CannotMakeBulletproof` or
`CannotMakeRangeProof`. Commitment parsing can still return `InvalidCommit`,
including from proof verification and rewind operations, so handle that error
alongside the operation-specific variants. Direct FFI users must also update
constructors, callbacks, pointer types, and count types to the new declarations.

// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.
use std::mem;

use libc::{c_int, c_uchar, c_uint, c_void, size_t};

/// Flag for context to enable no precomputation
pub const SECP256K1_START_NONE: c_uint = (1 << 0) | 0;
/// Flag for context to enable verification precomputation
pub const SECP256K1_START_VERIFY: c_uint = (1 << 0) | (1 << 8);
/// Flag for context to enable signing precomputation
pub const SECP256K1_START_SIGN: c_uint = (1 << 0) | (1 << 9);
/// Flag for keys to indicate uncompressed serialization format
pub const SECP256K1_SER_UNCOMPRESSED: c_uint = (1 << 1) | 0;
/// Flag for keys to indicate compressed serialization format
pub const SECP256K1_SER_COMPRESSED: c_uint = (1 << 1) | (1 << 8);

/// A nonce generation function. Ordinary users of the library
/// never need to see this type; only if you need to control
/// nonce generation do you need to use it. I have deliberately
/// made this hard to do: you have to write your own wrapper
/// around the FFI functions to use it. And it's an unsafe type.
/// Nonces are generated deterministically by RFC6979 by
/// default; there should be no need to ever change this.
pub type NonceFn = unsafe extern "C" fn(nonce32: *mut c_uchar,
                                        msg32: *const c_uchar,
                                        key32: *const c_uchar,
                                        algo16: *const c_uchar,
                                        attempt: c_uint,
                                        data: *const c_void);


/// A Secp256k1 context, containing various precomputed values and such
/// needed to do elliptic curve computations. If you create one of these
/// with `secp256k1_context_create` you MUST destroy it with
/// `secp256k1_context_destroy`, or else you will have a memory leak.
#[derive(Clone, Debug)]
#[repr(C)] pub struct Context(c_int);

/// Secp256k1 aggsig context. As above, needs to be destroyed with
/// `secp256k1_aggsig_context_destroy`
#[derive(Clone, Debug)]
#[repr(C)] pub struct AggSigContext(c_int);

/// Secp256k1 scratch space
#[derive(Clone, Debug)]
#[repr(C)] pub struct ScratchSpace(c_int);

/// Secp256k1 bulletproof generators
#[derive(Clone, Debug)]
#[repr(C)] pub struct BulletproofGenerators(c_int);

/// Generator
#[repr(C)] 
pub struct Generator(pub [c_uchar; 64]);
impl Copy for Generator {}
impl_array_newtype!(Generator, c_uchar, 64);
impl_raw_debug!(Generator);

/// Library-internal representation of a Secp256k1 public key
#[repr(C)]
pub struct PublicKey(pub [c_uchar; 64]);
impl Copy for PublicKey {}
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

impl PublicKey {
    /// Create a new (zeroed) public key usable for the FFI interface
    pub fn new() -> PublicKey { PublicKey([0; 64]) }
    /// Create a new (uninitialized) public key usable for the FFI interface
    pub unsafe fn blank() -> PublicKey { mem::MaybeUninit::uninit().assume_init() }
}

/// Library-internal representation of a Secp256k1 signature
#[repr(C)]
pub struct Signature(pub [c_uchar; 64]);
impl Copy for Signature {}
impl_array_newtype!(Signature, c_uchar, 64);
impl_raw_debug!(Signature);

/// Library-internal representation of a Secp256k1 signature + recovery ID
#[repr(C)]
pub struct RecoverableSignature([c_uchar; 65]);
impl Copy for RecoverableSignature {}
impl_array_newtype!(RecoverableSignature, c_uchar, 65);
impl_raw_debug!(RecoverableSignature);

/// Library-internal representation of a Secp256k1 aggsig partial signature
#[repr(C)]
pub struct AggSigPartialSignature([c_uchar; 32]);
impl Copy for AggSigPartialSignature {}
impl_array_newtype!(AggSigPartialSignature, c_uchar, 32);
impl_raw_debug!(AggSigPartialSignature);

impl Signature {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> Signature { Signature([0; 64]) }
    /// Create a signature from raw data
    pub fn from_data(data: [u8; 64]) -> Signature { Signature(data) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> Signature { mem::MaybeUninit::uninit().assume_init() }
}

impl RecoverableSignature {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> RecoverableSignature { RecoverableSignature([0; 65]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> RecoverableSignature { mem::MaybeUninit::uninit().assume_init() }
}

impl AggSigPartialSignature {
    /// Create a new (zeroed) aggsig partial signature usable for the FFI interface
    pub fn new() -> AggSigPartialSignature { AggSigPartialSignature([0; 32]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> AggSigPartialSignature { mem::MaybeUninit::uninit().assume_init() }
}

/// Library-internal representation of an ECDH shared secret
#[repr(C)]
pub struct SharedSecret([c_uchar; 32]);
impl_array_newtype!(SharedSecret, c_uchar, 32);
impl_raw_debug!(SharedSecret);

impl SharedSecret {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> SharedSecret { SharedSecret([0; 32]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> SharedSecret { mem::MaybeUninit::uninit().assume_init() }
}


extern "C" {
    pub static secp256k1_nonce_function_rfc6979: NonceFn;

    pub static secp256k1_nonce_function_default: NonceFn;

    // Contexts
    pub fn secp256k1_context_create(flags: c_uint) -> *mut Context;

    pub fn secp256k1_context_clone(cx: *mut Context) -> *mut Context;

    pub fn secp256k1_context_destroy(cx: *mut Context);

    pub fn secp256k1_context_randomize(cx: *mut Context,
                                       seed32: *const c_uchar)
                                       -> c_int;
    // Scratch space
    pub fn secp256k1_scratch_space_create(cx: *mut Context,
                                          max_size: size_t)
                                          -> *mut ScratchSpace;

    pub fn secp256k1_scratch_space_destroy(sp: *mut ScratchSpace);

    // Generator
    pub fn secp256k1_generator_generate(cx: *const Context,
                                        gen: *mut Generator,
                                        seed32: *const c_uchar)
                                        -> c_int;

    // TODO secp256k1_context_set_illegal_callback
    // TODO secp256k1_context_set_error_callback
    // (Actually, I don't really want these exposed; if either of these
    // are ever triggered it indicates a bug in rust-secp256k1, since
    // one goal is to use Rust's type system to eliminate all possible
    // bad inputs.)

    // Pubkeys
    pub fn secp256k1_ec_pubkey_parse(cx: *const Context, pk: *mut PublicKey,
                                     input: *const c_uchar, in_len: size_t)
                                     -> c_int;

    pub fn secp256k1_ec_pubkey_serialize(cx: *const Context, output: *const c_uchar,
                                         out_len: *mut size_t, pk: *const PublicKey,
                                         compressed: c_uint)
                                         -> c_int;

    // Signatures
    pub fn secp256k1_ecdsa_signature_parse_der(cx: *const Context, sig: *mut Signature,
                                               input: *const c_uchar, in_len: size_t)
                                               -> c_int;

    pub fn secp256k1_ecdsa_signature_parse_compact(cx: *const Context, sig: *mut Signature,
                                                   input64: *const c_uchar)
                                                   -> c_int;

    pub fn ecdsa_signature_parse_der_lax(cx: *const Context, sig: *mut Signature,
                                         input: *const c_uchar, in_len: size_t)
                                         -> c_int;

    pub fn secp256k1_ecdsa_signature_serialize_der(cx: *const Context, output: *const c_uchar,
                                                   out_len: *mut size_t, sig: *const Signature)
                                                   -> c_int;

    pub fn secp256k1_ecdsa_signature_serialize_compact(cx: *const Context, output64: *const c_uchar,
                                                       sig: *const Signature)
                                                       -> c_int;

    pub fn secp256k1_ecdsa_recoverable_signature_parse_compact(cx: *const Context, sig: *mut RecoverableSignature,
                                                               input64: *const c_uchar, recid: c_int)
                                                               -> c_int;

    pub fn secp256k1_ecdsa_recoverable_signature_serialize_compact(cx: *const Context, output64: *const c_uchar,
                                                                   recid: *mut c_int, sig: *const RecoverableSignature)
                                                                   -> c_int;

    pub fn secp256k1_ecdsa_recoverable_signature_convert(cx: *const Context, sig: *mut Signature,
                                                         input: *const RecoverableSignature)
                                                         -> c_int;

    pub fn secp256k1_ecdsa_signature_normalize(cx: *const Context, out_sig: *mut Signature,
                                               in_sig: *const Signature)
                                               -> c_int;

    // ECDSA
    pub fn secp256k1_ecdsa_verify(cx: *const Context,
                                  sig: *const Signature,
                                  msg32: *const c_uchar,
                                  pk: *const PublicKey)
                                  -> c_int;

    pub fn secp256k1_ecdsa_sign(cx: *const Context,
                                sig: *mut Signature,
                                msg32: *const c_uchar,
                                sk: *const c_uchar,
                                noncefn: NonceFn,
                                noncedata: *const c_void)
                                -> c_int;

    pub fn secp256k1_ecdsa_sign_recoverable(cx: *const Context,
                                            sig: *mut RecoverableSignature,
                                            msg32: *const c_uchar,
                                            sk: *const c_uchar,
                                            noncefn: NonceFn,
                                            noncedata: *const c_void)
                                            -> c_int;

    pub fn secp256k1_ecdsa_recover(cx: *const Context,
                                   pk: *mut PublicKey,
                                   sig: *const RecoverableSignature,
                                   msg32: *const c_uchar)
                                   -> c_int;
    // AGGSIG (Schnorr) Multisig
    pub fn secp256k1_aggsig_context_create(cx: *const Context,
                                           pks: *const PublicKey,
                                           n_pks: size_t,
                                           seed32: *const c_uchar)
                                           -> *mut AggSigContext;

    pub fn secp256k1_aggsig_context_destroy(aggctx: *mut AggSigContext);

    pub fn secp256k1_aggsig_generate_nonce(cx: *const Context,
                                           aggctx: *mut AggSigContext,
                                           index: size_t)
                                           -> c_int;

    pub fn secp256k1_aggsig_partial_sign(cx: *const Context,
                                         aggctx: *mut AggSigContext,
                                         sig: *mut AggSigPartialSignature,
                                         msghash32: *const c_uchar,
                                         seckey32: *const c_uchar,
                                         index: size_t)
                                           -> c_int;

    pub fn secp256k1_aggsig_combine_signatures(cx: *const Context,
                                         aggctx: *mut AggSigContext,
                                         sig64: *mut Signature,
                                         partial: *const AggSigPartialSignature,
                                         index: size_t)
                                           -> c_int;

    pub fn secp256k1_aggsig_build_scratch_and_verify(cx: *const Context,
                                                     sig64: *const Signature,
                                                     msg32: *const c_uchar,
                                                     pks: *const PublicKey,
                                                     n_pubkeys: size_t)
                                                         -> c_int;

    // AGGSIG (single sig or single-signer Schnorr)
    pub fn secp256k1_aggsig_export_secnonce_single(cx: *const Context,
                                                   secnonce32: *mut c_uchar,
                                                   seed32: *const c_uchar)
                                                       -> c_int;

    pub fn secp256k1_aggsig_sign_single(cx: *const Context,
                                        sig: *mut Signature,
                                        msg32: *const c_uchar,
                                        seckey32: *const c_uchar,
                                        secnonce32: *const c_uchar,
                                        extra32: *const c_uchar,
                                        pubnonce_for_e: *const PublicKey,
                                        pubnonce_total: *const PublicKey,
                                        pubkey_for_e: *const PublicKey,
                                        seed32: *const c_uchar)
                                           -> c_int;

    pub fn secp256k1_aggsig_verify_single(cx: *const Context,
                                          sig: *const Signature,
                                          msg32: *const c_uchar,
                                          pubnonce: *const PublicKey,
                                          pk: *const PublicKey,
                                          pk_total: *const PublicKey,
                                          extra_pubkey: *const PublicKey,
                                          is_partial: c_uint)
                                           -> c_int;

    pub fn secp256k1_schnorrsig_verify_batch(cx: *const Context,
                                             scratch: *mut ScratchSpace,
                                             sig: *const *const c_uchar,
                                             msg32: *const *const c_uchar,
                                             pk: *const *const PublicKey,
                                             n_sigs: size_t)
                                               -> c_int;

    pub fn secp256k1_aggsig_add_signatures_single(cx: *const Context,
                                                  ret_sig: *mut Signature,
                                                  sigs: *const *const c_uchar,
                                                  num_sigs: size_t,
                                                  pubnonce_total: *const PublicKey)
                                                      -> c_int;

    pub fn secp256k1_aggsig_subtract_partial_signature(cx: *const Context,
                                                  ret_partsig: *mut Signature,
                                                  ret_partsig_alt: *mut Signature,
                                                  sig: *const Signature,
                                                  part_sig: *const Signature)
                                                      -> c_int;

     // EC
    pub fn secp256k1_ec_seckey_verify(cx: *const Context,
                                      sk: *const c_uchar) -> c_int;

    pub fn secp256k1_ec_pubkey_create(cx: *const Context, pk: *mut PublicKey,
                                      sk: *const c_uchar) -> c_int;

//TODO secp256k1_ec_privkey_export
//TODO secp256k1_ec_privkey_import

    pub fn secp256k1_ec_privkey_tweak_add(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_add(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_privkey_tweak_mul(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_pubkey_tweak_mul(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    pub fn secp256k1_ec_pubkey_combine(cx: *const Context,
                                       out: *mut PublicKey,
                                       ins: *const *const PublicKey,
                                       n: c_int)
                                       -> c_int;

    pub fn secp256k1_ec_privkey_tweak_inv(cx: *const Context,
                                          sk: *mut c_uchar)
                                          -> c_int;

    pub fn secp256k1_ec_privkey_tweak_neg(cx: *const Context,
                                          sk: *mut c_uchar)
                                          -> c_int;

    pub fn secp256k1_ecdh(cx: *const Context,
                          out: *mut SharedSecret,
                          point: *const PublicKey,
                          scalar: *const c_uchar)
                          -> c_int;

  // Parse a 33-byte commitment into 64 byte internal commitment object
  pub fn secp256k1_pedersen_commitment_parse(cx: *const Context,
                                              commit: *mut c_uchar,
                                              input: *const c_uchar)
                                              -> c_int;

  // Serialize a 64-byte commit object into a 33 byte serialized byte sequence
  pub fn secp256k1_pedersen_commitment_serialize(cx: *const Context,
                                                  output: *mut c_uchar,
                                                  commit: *const c_uchar)
                                                  -> c_int;


	// Generates a pedersen commitment: *commit = blind * G + value * G2.
	// The commitment is 33 bytes, the blinding factor is 32 bytes.
	pub fn secp256k1_pedersen_commit(
		ctx: *const Context,
		commit: *mut c_uchar,
		blind: *const c_uchar,
		value: u64,
		value_gen: *const c_uchar,
		blind_gen: *const c_uchar
	) -> c_int;

	// Generates a pedersen commitment: *commit = blind * G + value * G2.
	// The commitment is 33 bytes, the blinding factor and the value are 32 bytes.
	pub fn secp256k1_pedersen_blind_commit(
		ctx: *const Context,
		commit: *mut c_uchar,
		blind: *const c_uchar,
		value: *const c_uchar,
		value_gen: *const c_uchar,
		blind_gen: *const c_uchar
	) -> c_int;

	// Get the public key of a pedersen commitment
	pub fn secp256k1_pedersen_commitment_to_pubkey(
	    cx: *const Context, pk: *mut PublicKey,
	    commit: *const c_uchar) -> c_int;

	// Get a pedersen commitment from a pubkey
	pub fn secp256k1_pubkey_to_pedersen_commitment(
	    cx: *const Context, commit: *mut c_uchar,
	    pk: *const PublicKey) -> c_int;

	// Takes a list of n pointers to 32 byte blinding values, the first negs
	// of which are treated with positive sign and the rest negative, then
	// calculates an additional blinding value that adds to zero.
	pub fn secp256k1_pedersen_blind_sum(
		ctx: *const Context,
		blind_out: *const c_uchar,
		blinds: *const *const c_uchar,
		n: size_t,
		npositive: size_t
	) -> c_int;

	// Takes two list of 64-byte commitments and sums the first set, subtracts
	// the second and returns the resulting commitment.
	pub fn secp256k1_pedersen_commit_sum(
		ctx: *const Context,
		commit_out: *const c_uchar,
		commits: *const *const c_uchar,
		pcnt: size_t,
		ncommits: *const *const c_uchar,
		ncnt: size_t
	) -> c_int;

    // Calculate blinding factor for switch commitment x + H(xG+vH | xJ)
    pub fn secp256k1_blind_switch(
        ctx: *const Context,
        blind_switch: *mut c_uchar,
        blind: *const c_uchar,
        value: u64,
        value_gen: *const c_uchar,
        blind_gen: *const c_uchar,
        switch_pubkey: *const c_uchar
    ) -> c_int;

	// Takes two list of 64-byte commitments and sums the first set and
	// subtracts the second and verifies that they sum to 0.
	pub fn secp256k1_pedersen_verify_tally(ctx: *const Context,
		commits: *const *const c_uchar,
		pcnt: size_t,
		ncommits: *const *const c_uchar,
		ncnt: size_t
	) -> c_int;

	pub fn secp256k1_rangeproof_info(
		ctx: *const Context,
		exp: *mut c_int,
		mantissa: *mut c_int,
		min_value: *mut u64,
		max_value: *mut u64,
		proof: *const c_uchar,
		plen: size_t
	) -> c_int;

	pub fn secp256k1_rangeproof_rewind(
		ctx: *const Context,
		blind_out: *mut c_uchar,
		value_out: *mut u64,
		message_out: *mut c_uchar,
		outlen: *mut size_t,
		nonce: *const c_uchar,
		min_value: *mut u64,
		max_value: *mut u64,
		commit: *const c_uchar,
		proof: *const c_uchar,
		plen: size_t,
		extra_commit: *const c_uchar,
		extra_commit_len: size_t,
		gen: *const c_uchar
	) -> c_int;

	pub fn secp256k1_rangeproof_verify(
		ctx: *const Context,
		min_value: &mut u64,
		max_value: &mut u64,
		commit: *const c_uchar,
		proof: *const c_uchar,
		plen: size_t,
		extra_commit: *const c_uchar,
		extra_commit_len: size_t,
		gen: *const c_uchar
	) -> c_int;

	pub fn secp256k1_rangeproof_sign(
		ctx: *const Context,
		proof: *mut c_uchar,
		plen: *mut size_t,
		min_value: u64,
		commit: *const c_uchar,
		blind: *const c_uchar,
		nonce: *const c_uchar,
		exp: c_int,
		min_bits: c_int,
		value: u64,
		message: *const c_uchar,
		msg_len: size_t,
		extra_commit: *const c_uchar,
		extra_commit_len: size_t,
		gen: *const c_uchar
	) -> c_int;

	pub fn secp256k1_bulletproof_generators_create(
		ctx: *const Context,
		blinding_gen: *const c_uchar,
		n: size_t,
	) -> *mut BulletproofGenerators;

	pub fn secp256k1_bulletproof_generators_destroy(
		ctx: *const Context,
		gen: *mut BulletproofGenerators,
	);

	pub fn secp256k1_bulletproof_rangeproof_prove(
		ctx: *const Context,
		scratch: *mut ScratchSpace,
		gens: *const BulletproofGenerators,
		proof: *mut c_uchar,
		plen: *mut size_t,
		tau_x: *mut c_uchar,
		t_one: *mut PublicKey,
		t_two: *mut PublicKey,
		value: *const u64,
		min_value: *const u64,
		blind: *const *const c_uchar,
		commits: *const *const c_uchar,
		n_commits: size_t,
		value_gen: *const c_uchar,
		nbits: size_t,
		nonce: *const c_uchar,
		private_nonce: *const c_uchar,
		extra_commit: *const c_uchar,
		extra_commit_len: size_t,
		message: *const c_uchar,
	) -> c_int;

	pub fn secp256k1_bulletproof_rangeproof_verify(
		ctx: *const Context,
		scratch: *mut ScratchSpace,
		gens: *const BulletproofGenerators,
		proof: *const c_uchar,
		plen: size_t,
		min_value: *const u64,
		commit: *const c_uchar,
		n_commits: size_t,
		nbits: size_t,
		value_gen: *const c_uchar,
		extra_commit: *const c_uchar,
		extra_commit_len: size_t
	) -> c_int;

	pub fn secp256k1_bulletproof_rangeproof_verify_multi(
		ctx: *const Context,
		scratch: *mut ScratchSpace,
		gens: *const BulletproofGenerators,
		proofs: *const *const c_uchar,
		n_proofs: size_t,
		plen: size_t,
		min_value: *const *const u64,
		commits: *const *const c_uchar,
		n_commits: size_t,
		nbits: size_t,
		value_gen: *const c_uchar,
		extra_commit: *const *const c_uchar,
		extra_commit_len: *const size_t
	) -> c_int;

	pub fn secp256k1_bulletproof_rangeproof_rewind(
		ctx: *const Context,
		value: *mut u64,
		blind: *mut c_uchar,
		proof: *const c_uchar,
		plen: size_t,
		min_value: u64,
		commit: *const c_uchar,
		value_gen: *const c_uchar,
		nonce: *const c_uchar,
		extra_commit: *const c_uchar,
		extra_commit_len: size_t,
		message: *mut c_uchar,
	) -> c_int;
}

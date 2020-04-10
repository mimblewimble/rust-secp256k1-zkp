// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
// 2018 The Grin Developers
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

//! # Pedersen commitments and related range proofs

use libc::size_t;
use std::cmp::min;
use std::fmt;
use std::mem;
use std::ptr;
use std::u64;

use crate::ContextFlag;
use crate::Error::{self, InvalidPublicKey, InvalidCommit};
use crate::Secp256k1;

use super::{Message, Signature};
use crate::aggsig::ZERO_256;
use crate::constants;
use crate::ffi;
use crate::key::{self, PublicKey, SecretKey};
use rand::{thread_rng, Rng};
use serde::{de, ser};

const MAX_WIDTH: usize = 1 << 20;
const SCRATCH_SPACE_SIZE: size_t = 256 * MAX_WIDTH;
const MAX_GENERATORS: size_t = 256;

/// Shared Bullet Proof Generators (avoid recreating every time)
static mut SHARED_BULLETGENERATORS: Option<*mut ffi::BulletproofGenerators> = None;

// TODO: Check whether this matters if this is used with a different context; don't think it does
fn shared_generators(ctx: *mut ffi::Context) -> *mut ffi::BulletproofGenerators {
	unsafe {
		match SHARED_BULLETGENERATORS.clone() {
			Some(s) => s,
			None => {
				SHARED_BULLETGENERATORS = Some(ffi::secp256k1_bulletproof_generators_create(
					ctx,
					constants::GENERATOR_G.as_ptr(),
					MAX_GENERATORS,
				));
				SHARED_BULLETGENERATORS.unwrap()
			}
		}
	}
}

/// underling lib's representation of a commit, which is now a full 64 bytes
pub struct CommitmentInternal(pub [u8; constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL]);
impl Copy for CommitmentInternal {}
impl_array_newtype!(CommitmentInternal, u8, constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL);
impl_pretty_debug!(CommitmentInternal);


impl CommitmentInternal {
	/// Uninitialized commitment, use with caution
	pub unsafe fn blank() -> CommitmentInternal {
		mem::MaybeUninit::uninit().assume_init()
	}
}

/// A Pedersen commitment
pub struct Commitment(pub [u8; constants::PEDERSEN_COMMITMENT_SIZE]);
impl Copy for Commitment {}
impl_array_newtype!(Commitment, u8, constants::PEDERSEN_COMMITMENT_SIZE);
impl_pretty_debug!(Commitment);

impl Commitment {
	/// Builds a Hash from a byte vector. If the vector is too short, it will be
	/// completed by zeroes. If it's too long, it will be truncated.
	pub fn from_vec(v: Vec<u8>) -> Commitment {
		let mut h = [0; constants::PEDERSEN_COMMITMENT_SIZE];
		for i in 0..min(v.len(), constants::PEDERSEN_COMMITMENT_SIZE) {
			h[i] = v[i];
		}
		Commitment(h)
	}

	/// Uninitialized commitment, use with caution
	unsafe fn blank() -> Commitment {
		mem::MaybeUninit::uninit().assume_init()
	}

	/// Creates from a pubkey
	pub fn from_pubkey(secp: &Secp256k1, pk: &key::PublicKey) -> Result<Self, Error> {
		unsafe {
			let mut commit_i = [0; constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL];
			if ffi::secp256k1_pubkey_to_pedersen_commitment(secp.ctx, commit_i.as_mut_ptr(), &pk.0 as *const _) == 1 {
				Ok(secp.commit_ser(commit_i)?)
			} else {
				Err(InvalidCommit)
			}
		}
	}

	/// Converts a commitment to a public key
	pub fn to_pubkey(&self, secp: &Secp256k1) -> Result<key::PublicKey, Error> {
		let mut pk = unsafe { ffi::PublicKey::blank() };
		unsafe {
			let commit = secp.commit_parse(self.0.clone())?;
			if ffi::secp256k1_pedersen_commitment_to_pubkey(secp.ctx, &mut pk, commit.as_ptr()) == 1 {
				Ok(key::PublicKey::from_secp256k1_pubkey(pk))
			} else {
				Err(InvalidPublicKey)
			}
		}
	}

}

/// A range proof. Typically much larger in memory that the above (~5k).
#[derive(Copy)]
pub struct RangeProof {
	/// The proof itself, at most 5134 bytes long
	pub proof: [u8; constants::MAX_PROOF_SIZE],
	/// The length of the proof
	pub plen: usize,
}

impl PartialEq for RangeProof {
	fn eq(&self, other: &Self) -> bool {
		self.proof.as_ref() == other.proof.as_ref()
	}
}

impl Clone for RangeProof {
	#[inline]
	fn clone(&self) -> RangeProof {
		unsafe {
			use std::ptr::copy_nonoverlapping;
			let mut ret: [u8; constants::MAX_PROOF_SIZE] = mem::MaybeUninit::uninit().assume_init();
			copy_nonoverlapping(
				self.proof.as_ptr(),
				ret.as_mut_ptr(),
				mem::size_of::<RangeProof>(),
			);
			RangeProof {
				proof: ret,
				plen: self.plen,
			}
		}
	}
}

impl ser::Serialize for RangeProof {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: ser::Serializer,
	{
		(&self.proof[..self.plen]).serialize(s)
	}
}

struct Visitor;

impl<'di> de::Visitor<'di> for Visitor {
	type Value = RangeProof;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("an array of bytes")
	}

	#[inline]
	fn visit_seq<V>(self, mut v: V) -> Result<RangeProof, V::Error>
	where
		V: de::SeqAccess<'di>,
	{
		unsafe {
			let mut ret: [u8; constants::MAX_PROOF_SIZE] = mem::MaybeUninit::uninit().assume_init();
			let mut i = 0;
			while let Some(val) = v.next_element()? {
				ret[i] = val;
				i += 1;
			}
			Ok(RangeProof {
				proof: ret,
				plen: i,
			})
		}
	}
}

impl<'de> de::Deserialize<'de> for RangeProof {
	fn deserialize<D>(d: D) -> Result<RangeProof, D::Error>
	where
		D: de::Deserializer<'de>,
	{
		// Begin actual function
		d.deserialize_seq(Visitor)
	}
}

impl AsRef<[u8]> for RangeProof {
	fn as_ref(&self) -> &[u8] {
		&self.proof[..self.plen as usize]
	}
}

// This is a macro that check zero public key
macro_rules! is_zero_pubkey {
	(retnone => $e:expr) => {
		match $e {
			Some(n) => {
				if (n.0).0.starts_with(&ZERO_256) {
					return None;
					}
				n.as_mut_ptr()
				}
			None => ptr::null_mut(),
			}
	};
	(ignore => $e:expr) => {
		match $e {
			Some(n) => n.as_mut_ptr(),
			None => ptr::null_mut(),
			}
	};
}

impl RangeProof {
	/// Create the zero range proof
	pub fn zero() -> RangeProof {
		RangeProof {
			proof: [0; constants::MAX_PROOF_SIZE],
			plen: 0,
		}
	}
	/// The range proof as a byte slice.
	pub fn bytes(&self) -> &[u8] {
		&self.proof[..self.plen as usize]
	}
	/// Length of the range proof in bytes.
	pub fn len(&self) -> usize {
		self.plen
	}
}

/// A message included in a range proof.
/// The message is recoverable by rewinding a range proof
/// passing in the same nonce that was used to originally create the range proof.
#[derive(Clone)]
pub struct ProofMessage(Vec<u8>);

impl ProofMessage {
	/// Creates an empty message.
	pub fn empty() -> ProofMessage {
		ProofMessage(vec![])
	}

	/// Creates a message from a byte slice.
	pub fn from_bytes(array: &[u8]) -> ProofMessage {
		let mut msg = vec![];
		for &value in array {
			msg.push(value);
		}
		ProofMessage(msg)
	}

	/// Converts the message to a byte slice.
	pub fn as_bytes(&self) -> &[u8] {
		self.0.iter().as_slice()
	}

	/// Converts the message to a raw pointer.
	pub fn as_ptr(&self) -> *const u8 {
		self.0.as_ptr()
	}

	/// The length of the message.
	/// This will be PROOF_MSG_SIZE unless the message has been truncated.
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Message in the range proof is the first len bytes of the fixed PROOF_MSG_SIZE.
	/// We can truncate it to the correct size if we know how many bytes we care about.
	/// This probably implies the message will take a known format.
	pub fn truncate(&mut self, len: usize) {
		self.0.truncate(len)
	}

	/// Push a byte onto the message
	pub fn push(&mut self, value: u8) {
		self.0.push(value);
	}
}

impl ::std::cmp::PartialEq for ProofMessage {
	fn eq(&self, other: &ProofMessage) -> bool {
		self.0[..] == other.0[..]
	}
}
impl ::std::cmp::Eq for ProofMessage {}

impl ::std::fmt::Debug for ProofMessage {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		write!(f, "{}(", stringify!(ProofMessage))?;
		for i in self.0.iter().cloned() {
			write!(f, "{:02x}", i)?;
		}
		write!(f, ")")
	}
}

/// The range that was proven
#[derive(Debug)]
pub struct ProofRange {
	/// Min value that was proven
	pub min: u64,
	/// Max value that was proven
	pub max: u64,
}

/// Information about a valid proof after rewinding it.
#[derive(Debug)]
pub struct ProofInfo {
	/// Whether the proof is valid or not
	pub success: bool,
	/// Value that was used by the commitment
	pub value: u64,
	/// Blinding factor that was used (Bulletproofs)
	pub blinding: SecretKey,
	/// Message embedded in the proof
	pub message: ProofMessage,
	/// Length of the embedded message (message is "padded" with garbage to fixed number of bytes)
	pub mlen: usize,
	/// Min value that was proven
	pub min: u64,
	/// Max value that was proven
	pub max: u64,
	/// Exponent used by the proof
	pub exp: i32,
	/// Mantissa used by the proof
	pub mantissa: i32,
}

impl ::std::fmt::Debug for RangeProof {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		write!(f, "{}(", stringify!(RangeProof))?;
		for i in self.proof[..self.plen].iter().cloned() {
			write!(f, "{:02x}", i)?;
		}
		write!(f, ")[{}]", self.plen)
	}
}

impl Secp256k1 {
	/// verify commitment
	pub fn verify_from_commit(
		&self,
		msg: &Message,
		sig: &Signature,
		commit: &Commitment,
	) -> Result<(), Error> {
		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}

		let pubkey = commit.to_pubkey(&self).unwrap();

		let result = self.verify(msg, sig, &pubkey);
		match result {
			Ok(x) => Ok(x),
			Err(_) => result,
		}
	}

	/// Parse a commit into an internal representation
	fn commit_parse(&self, c_in: [u8;constants::PEDERSEN_COMMITMENT_SIZE])
	-> Result<CommitmentInternal, Error> {
		let c_out = unsafe {
			let mut c_out = CommitmentInternal::blank();
			ffi::secp256k1_pedersen_commitment_parse(
				self.ctx,
				c_out.as_mut_ptr(),
				c_in.as_ptr(),
			);
			c_out
		};
		Ok(c_out)
	}

	/// Parse a commit into an internal representation
	fn commit_ser(&self, c_in: [u8;constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL])
	-> Result<Commitment, Error> {
		let c_out = unsafe {
			let mut c_out = Commitment::blank();
			ffi:: secp256k1_pedersen_commitment_serialize(
				self.ctx,
				c_out.as_mut_ptr(),
				c_in.as_ptr(),
			);
			c_out
		};
		Ok(c_out)
	}

	/// Creates a pedersen commitment from a value and a blinding factor
	pub fn commit(&self, value: u64, blind: SecretKey) -> Result<Commitment, Error> {
		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}
		let mut commit_i = [0; constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL];
		unsafe {
			ffi::secp256k1_pedersen_commit(
				self.ctx,
				commit_i.as_mut_ptr(),
				blind.as_ptr(),
				value,
				constants::GENERATOR_H.as_ptr(),
				constants::GENERATOR_G.as_ptr(),
			)
		};
		Ok(self.commit_ser(commit_i)?)
	}

	/// Creates a pedersen commitment from a two blinding factors
	pub fn commit_blind(&self, value: SecretKey, blind: SecretKey) -> Result<Commitment, Error> {
		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}
		let mut commit_i = [0; constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL];
		unsafe {
			ffi::secp256k1_pedersen_blind_commit(
				self.ctx,
				commit_i.as_mut_ptr(),
				blind.as_ptr(),
				value.as_ptr(),
				constants::GENERATOR_H.as_ptr(),
				constants::GENERATOR_G.as_ptr(),
			)
		};
		Ok(self.commit_ser(commit_i)?)
	}

	/// Convenience method to Create a pedersen commitment only from a value,
	/// with a zero blinding factor
	pub fn commit_value(&self, value: u64) -> Result<Commitment, Error> {
		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}
		let mut commit_i = [0; constants::PEDERSEN_COMMITMENT_SIZE_INTERNAL];
		let zblind = [0u8; 32];

		unsafe {
			ffi::secp256k1_pedersen_commit(
				self.ctx,
				commit_i.as_mut_ptr(),
				zblind.as_ptr(),
				value,
				constants::GENERATOR_H.as_ptr(),
				constants::GENERATOR_G.as_ptr(),
			)
		};
		Ok(self.commit_ser(commit_i)?)
	}

	/// Taking vectors of positive and negative commitments as well as an
	/// expected excess, verifies that it all sums to zero.
	pub fn verify_commit_sum(&self, positive: Vec<Commitment>, negative: Vec<Commitment>) -> bool {
		let pos = map_vec!(positive, |p| { self.commit_parse(p.0).unwrap() });
		let neg = map_vec!(negative, |n| self.commit_parse(n.0).unwrap());
		let pos = map_vec!(pos, |p| p.0.as_ptr());
		let neg = map_vec!(neg, |n| n.0.as_ptr());
		unsafe {
			ffi::secp256k1_pedersen_verify_tally(
				self.ctx,
				pos.as_ptr(),
				pos.len() as size_t,
				neg.as_ptr(),
				neg.len() as size_t,
			) == 1
		}
	}

	/// Computes the sum of multiple positive and negative pedersen commitments.
	pub fn commit_sum(
		&self,
		positive: Vec<Commitment>,
		negative: Vec<Commitment>,
	) -> Result<Commitment, Error> {
		let pos = map_vec!(positive, |p| self.commit_parse(p.0).unwrap());
		let neg = map_vec!(negative, |n| self.commit_parse(n.0).unwrap());
		let pos = map_vec!(pos, |p| p.0.as_ptr());
		let neg = map_vec!(neg, |n| n.0.as_ptr());
		let mut ret_i = unsafe { CommitmentInternal::blank() };
		let err = unsafe {
			ffi::secp256k1_pedersen_commit_sum(
				self.ctx,
				ret_i.as_mut_ptr(),
				pos.as_ptr(),
				pos.len() as size_t,
				neg.as_ptr(),
				neg.len() as size_t,
			)
		};
		if err == 1 {
			Ok(self.commit_ser(ret_i.0)?)
		} else {
			Err(Error::IncorrectCommitSum)
		}
	}

	/// Computes the sum of multiple positive and negative blinding factors.
	pub fn blind_sum(
		&self,
		positive: Vec<SecretKey>,
		negative: Vec<SecretKey>,
	) -> Result<SecretKey, Error> {
		let mut neg = map_vec!(negative, |n| n.as_ptr());
		let mut all = map_vec!(positive, |p| p.as_ptr());
		all.append(&mut neg);
		let mut ret: [u8; 32] = unsafe { mem::MaybeUninit::uninit().assume_init() };
		unsafe {
			assert_eq!(
				ffi::secp256k1_pedersen_blind_sum(
					self.ctx,
					ret.as_mut_ptr(),
					all.as_ptr(),
					all.len() as size_t,
					positive.len() as size_t,
				),
				1
			);
		}
		// secp256k1 should never return an invalid private
		SecretKey::from_slice(self, &ret)
	}

	/// Compute a blinding factor using a switch commitment
	pub fn blind_switch(&self, value: u64, blind: SecretKey) -> Result<SecretKey, Error> {
		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}
		let mut ret: [u8; 32] = unsafe { mem::MaybeUninit::uninit().assume_init() };
		unsafe {
			assert_eq!(
				ffi::secp256k1_blind_switch(
					self.ctx,
					ret.as_mut_ptr(),
					blind.as_ptr(),
					value,
					constants::GENERATOR_H.as_ptr(),
					constants::GENERATOR_G.as_ptr(),
					constants::GENERATOR_PUB_J_RAW.as_ptr(),
				),
				1
			)
		}
		SecretKey::from_slice(self, &ret)
	}

	/// Convenience function for generating a random nonce for a range proof.
	/// We will need the nonce later if we want to rewind the range proof.
	pub fn nonce(&self) -> [u8; 32] {
		thread_rng().gen::<[u8; 32]>()
	}

	/// Produces a range proof for the provided value, using min and max
	/// bounds, relying
	/// on the blinding factor and commitment.
	pub fn range_proof(
		&self,
		min: u64,
		value: u64,
		blind: SecretKey,
		commit: Commitment,
		message: ProofMessage,
	) -> RangeProof {
		let mut retried = false;
		let mut proof = [0; constants::MAX_PROOF_SIZE];
		let mut plen = constants::MAX_PROOF_SIZE as size_t;

		// use a "known key" as the nonce, specifically the blinding factor
		// of the commitment for which we are generating the range proof
		// so we can later recover the value and the message by unwinding the range proof
		// with the same nonce
		let nonce = blind.clone();

		let extra_commit = [0u8; 33];

		let commit = self.commit_parse(commit.0).unwrap();

		// TODO - confirm this reworked retry logic works as expected
		// pretty sure the original approach retried on success (so twice in total)
		// and just kept looping forever on error
		loop {
			let success = unsafe {
				// because: "This can randomly fail with probability around one in 2^100.
				// If this happens, buy a lottery ticket and retry."
				ffi::secp256k1_rangeproof_sign(
					self.ctx,
					proof.as_mut_ptr(),
					&mut plen,
					min,
					commit.as_ptr(),
					blind.as_ptr(),
					nonce.as_ptr(),
					0,
					64,
					value,
					message.as_ptr(),
					message.len(),
					extra_commit.as_ptr(),
					0 as size_t,
					constants::GENERATOR_H.as_ptr(),
				) == 1
			};
			// break out of the loop immediately on success or
			// or on the 2nd attempt if we retried
			if success || retried {
				break;
			} else {
				retried = true;
			}
		}
		RangeProof {
			proof: proof,
			plen: plen as usize,
		}
	}

	/// Verify a proof that a committed value is within a range.
	pub fn verify_range_proof(
		&self,
		commit: Commitment,
		proof: RangeProof,
	) -> Result<ProofRange, Error> {
		let mut min: u64 = 0;
		let mut max: u64 = 0;

		let extra_commit = [0u8; 33];

		let commit = self.commit_parse(commit.0)?;

		let success = unsafe {
			ffi::secp256k1_rangeproof_verify(
				self.ctx,
				&mut min,
				&mut max,
				commit.as_ptr(),
				proof.proof.as_ptr(),
				proof.plen as size_t,
				extra_commit.as_ptr(),
				0 as size_t,
				constants::GENERATOR_H.as_ptr(),
			) == 1
		};

		if success {
			Ok(ProofRange { min: min, max: max })
		} else {
			Err(Error::InvalidRangeProof)
		}
	}

	/// Verify a range proof and rewind the proof to recover information
	/// sent by its author.
	pub fn rewind_range_proof(
		&self,
		commit: Commitment,
		proof: RangeProof,
		nonce: SecretKey,
	) -> ProofInfo {
		let mut value: u64 = 0;
		let mut blind: [u8; 32] = unsafe { mem::MaybeUninit::uninit().assume_init() };
		let mut message: [u8; constants::PROOF_MSG_SIZE] = unsafe { mem::MaybeUninit::uninit().assume_init() };
		let mut mlen: usize = constants::PROOF_MSG_SIZE;
		let mut min: u64 = 0;
		let mut max: u64 = 0;

		let extra_commit = [0u8; 33];

		let commit = self.commit_parse(commit.0).unwrap();

		let success = unsafe {
			ffi::secp256k1_rangeproof_rewind(
				self.ctx,
				blind.as_mut_ptr(),
				&mut value,
				message.as_mut_ptr(),
				&mut mlen,
				nonce.as_ptr(),
				&mut min,
				&mut max,
				commit.as_ptr(),
				proof.proof.as_ptr(),
				proof.plen as size_t,
				extra_commit.as_ptr(),
				0 as size_t,
				constants::GENERATOR_H.as_ptr(),
			) == 1
		};

		ProofInfo {
			success: success,
			value: value,
			message: ProofMessage::from_bytes(&message),
			blinding: SecretKey([0; constants::SECRET_KEY_SIZE]),
			mlen: mlen,
			min: min,
			max: max,
			exp: 0,
			mantissa: 0,
		}
	}

	/// General information extracted from a range proof. Does not provide any
	/// information about the value or the message (see rewind).
	pub fn range_proof_info(&self, proof: RangeProof) -> ProofInfo {
		let mut exp: i32 = 0;
		let mut mantissa: i32 = 0;
		let mut min: u64 = 0;
		let mut max: u64 = 0;

		let success = unsafe {
			ffi::secp256k1_rangeproof_info(
				self.ctx,
				&mut exp,
				&mut mantissa,
				&mut min,
				&mut max,
				proof.proof.as_ptr(),
				proof.plen as size_t,
			) == 1
		};
		ProofInfo {
			success: success,
			value: 0,
			message: ProofMessage::empty(),
			blinding: SecretKey([0; constants::SECRET_KEY_SIZE]),
			mlen: 0,
			min: min,
			max: max,
			exp: exp,
			mantissa: mantissa,
		}
	}

	/// Produces a bullet proof for the provided value, using min and max
	/// bounds, relying on the blinding factor and value. If a message is passed,
	/// it will be truncated or padded to exactly BULLET_PROOF_MSG_SIZE bytes
	pub fn bullet_proof(
		&self,
		value: u64,
		blind: SecretKey,
		rewind_nonce: SecretKey,
		private_nonce: SecretKey,
		extra_data_in: Option<Vec<u8>>,
		message: Option<ProofMessage>,
	) -> RangeProof {
		let mut proof = [0; constants::MAX_PROOF_SIZE];
		let mut plen = constants::MAX_PROOF_SIZE as size_t;

		let blind_vec: Vec<SecretKey> = vec![blind];
		let blind_vec = map_vec!(blind_vec, |p| p.0.as_ptr());
		let n_bits = 64;

		let (extra_data_len, extra_data) = match extra_data_in.as_ref() {
			Some(d) => (d.len(), d.as_ptr()),
			None => (0, ptr::null()),
		};

		let mut message = message;
		let message_ptr = match message.as_mut() {
			Some(m) => {
				while m.len() < constants::BULLET_PROOF_MSG_SIZE {
					m.push(0u8);
				}
				m.truncate(constants::BULLET_PROOF_MSG_SIZE);
				m.as_ptr()
			},
			None => ptr::null(),
		};

		// This api is not for multi-party range proof, so all null for these 4 parameters.
		let tau_x = ptr::null_mut();
		let t_one = ptr::null_mut();
		let t_two = ptr::null_mut();
		let commits = ptr::null_mut();

		let _success = unsafe {
			let scratch = ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SPACE_SIZE);
			let result = ffi::secp256k1_bulletproof_rangeproof_prove(
				self.ctx,
				scratch,
				shared_generators(self.ctx),
				proof.as_mut_ptr(),
				&mut plen,
				tau_x,
				t_one,
				t_two,
				&value,
				ptr::null(), // min_values: NULL for all-zeroes minimum values to prove ranges above
				blind_vec.as_ptr(),
				commits,
				1,
				constants::GENERATOR_H.as_ptr(),
				n_bits as size_t,
				rewind_nonce.as_ptr(),
				private_nonce.as_ptr(),
				extra_data,
				extra_data_len as size_t,
				message_ptr,
			);

			//			ffi::secp256k1_bulletproof_generators_destroy(self.ctx, *gens);
			ffi::secp256k1_scratch_space_destroy(scratch);

			result == 1
		};

		RangeProof {
			proof: proof,
			plen: plen as usize,
		}
	}

	/// Produces a bullet proof for multi-party commitment
	pub fn bullet_proof_multisig(
		&self,
		value: u64,
		blind: SecretKey,
		nonce: SecretKey,
		extra_data_in: Option<Vec<u8>>,
		message: Option<ProofMessage>,
		tau_x: Option<&mut SecretKey>,
		t_one: Option<&mut PublicKey>,
		t_two: Option<&mut PublicKey>,
		commits: Vec<Commitment>,
		private_nonce: Option<&SecretKey>,
		step: u8, // 0 for last step. 1 for first step.
	) -> Option<RangeProof> {
		let last_step = if 0 == step { true } else { false };
		let first_step = if 1 == step { true } else { false };

		let mut proof = [0; constants::MAX_PROOF_SIZE];
		let mut plen = constants::MAX_PROOF_SIZE as size_t;

		let blind_vec: Vec<SecretKey> = vec![blind];
		let blind_vec = map_vec!(blind_vec, |p| p.0.as_ptr());
		let n_bits = 64;

		let (extra_data_len, extra_data) = match extra_data_in.as_ref() {
			Some(d) => (d.len(), d.as_ptr()),
			None => (0, ptr::null()),
		};

		let mut message = message;
		let message_ptr = match message.as_mut() {
			Some(m) => {
				while m.len() < constants::BULLET_PROOF_MSG_SIZE {
					m.push(0u8);
				}
				m.truncate(constants::BULLET_PROOF_MSG_SIZE);
				m.as_ptr()
			},
			None => ptr::null(),
		};

		let tau_x = match tau_x {
			Some(n) => n.0.as_mut_ptr(),
			None => ptr::null_mut(),
		};

		let t_one_ptr;
		let t_two_ptr;
		if first_step {
			t_one_ptr = is_zero_pubkey!(ignore  => t_one);
			t_two_ptr = is_zero_pubkey!(ignore  => t_two);
		} else {
			t_one_ptr = is_zero_pubkey!(retnone => t_one);
			t_two_ptr = is_zero_pubkey!(retnone => t_two);
		};

		let commit_vec;
		let commit_ptr_vec;
		let commit_ptr_vec_ptr = if commits.len() > 0 {
			commit_vec = map_vec!(commits, |c| self.commit_parse(c.0).unwrap());
			commit_ptr_vec = map_vec!(commit_vec, |c| c.as_ptr());
			commit_ptr_vec.as_ptr()
		} else {
			ptr::null()
		};

		let private_nonce = match private_nonce {
			Some(n) => n.as_ptr(),
			None => ptr::null(),
		};

		let _success = unsafe {
			let scratch = ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SPACE_SIZE);
			let result = ffi::secp256k1_bulletproof_rangeproof_prove(
				self.ctx,
				scratch,
				shared_generators(self.ctx),
				if last_step {
					proof.as_mut_ptr()
				} else {
					ptr::null_mut()
				},
				if last_step {
					&mut plen
				} else {
					ptr::null_mut()
				},
				tau_x,
				t_one_ptr,
				t_two_ptr,
				&value,
				ptr::null(), // min_values: NULL for all-zeroes minimum values to prove ranges above
				blind_vec.as_ptr(),
				commit_ptr_vec_ptr,
				1,
				constants::GENERATOR_H.as_ptr(),
				n_bits as size_t,
				nonce.as_ptr(),
				private_nonce,
				extra_data,
				extra_data_len as size_t,
				message_ptr,
			);

			ffi::secp256k1_scratch_space_destroy(scratch);

			result == 1
		};

		if last_step {
			Some(RangeProof {
				proof: proof,
				plen: plen as usize,
			})
		} else {
			None
		}
	}

	/// Verify with bullet proof that a committed value is positive
	pub fn verify_bullet_proof(
		&self,
		commit: Commitment,
		proof: RangeProof,
		extra_data_in: Option<Vec<u8>>,
	) -> Result<ProofRange, Error> {
		let n_bits = 64;

		let extra_data;
		let (extra_data_len, extra_data) = match extra_data_in {
			Some(d) => {
				extra_data = d;
				(extra_data.len(), extra_data.as_ptr())
			},
			None => (0, ptr::null()),
		};

		let commit = self.commit_parse(commit.0).unwrap();

		let success = unsafe {
			let scratch = ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SPACE_SIZE);
			let result = ffi::secp256k1_bulletproof_rangeproof_verify(
				self.ctx,
				scratch,
				shared_generators(self.ctx),
				proof.proof.as_ptr(),
				proof.plen as size_t,
				ptr::null(), // min_values: NULL for all-zeroes minimum values to prove ranges above
				commit.0.as_ptr(),
				1,
				n_bits as size_t,
				constants::GENERATOR_H.as_ptr(),
				extra_data,
				extra_data_len as size_t,
			);
			//			ffi::secp256k1_bulletproof_generators_destroy(self.ctx, gens);
			ffi::secp256k1_scratch_space_destroy(scratch);
			result == 1
		};

		if success {
			Ok(ProofRange {
				min: 0,
				max: u64::MAX,
			})
		} else {
			Err(Error::InvalidRangeProof)
		}
	}

	/// Verify with bullet proof that a committed value is positive
	pub fn verify_bullet_proof_multi(
		&self,
		commits: Vec<Commitment>,
		proofs: Vec<RangeProof>,
		extra_data_in: Option<Vec<Vec<u8>>>,
	) -> Result<ProofRange, Error> {
		let n_bits = 64;

		let proof_size = if proofs.len() > 0 {
			proofs[0].plen
		} else {
			constants::SINGLE_BULLET_PROOF_SIZE
		};

		let commit_vec = map_vec!(commits, |c| self.commit_parse(c.0).unwrap());
		let commit_vec = map_vec!(commit_vec, |c| c.as_ptr());
		let proof_vec = map_vec!(proofs, |p| p.proof.as_ptr());
		//		let min_values = vec![0; proofs.len()];

		// array of generator multiplied by value in pedersen commitments (cannot be NULL)
		let value_gen_vec = {
			let min_len = if proof_vec.len() > 0 {
				proof_vec.len()
			} else {
				1
			};
			let gen_size = constants::GENERATOR_SIZE;
			let mut value_gen_vec = vec![0; min_len * gen_size];
			for i in 0..min_len {
				value_gen_vec[i * gen_size..(i + 1) * gen_size]
					.clone_from_slice(&constants::GENERATOR_H[..]);
			}
			value_gen_vec
		};

		// converting vec of vecs to expected pointer
		let (extra_data_vec, extra_data_lengths) = match extra_data_in.as_ref() {
			Some(ed) => {
				let extra_data_vec = map_vec!(ed, |d| d.as_ptr());
				let extra_data_lengths = map_vec![ed, |d| d.len()];
				(extra_data_vec, extra_data_lengths)
			}
			None => {
				let extra_data_vec = vec![ptr::null(); proof_vec.len()];
				let extra_data_lengths = vec![0; proof_vec.len()];
				(extra_data_vec, extra_data_lengths)
			}
		};

		let success = unsafe {
			let scratch = ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SPACE_SIZE);
			let result = ffi::secp256k1_bulletproof_rangeproof_verify_multi(
				self.ctx,
				scratch,
				shared_generators(self.ctx),
				proof_vec.as_ptr(),
				proof_vec.len(),
				proof_size,
				ptr::null(), // min_values: NULL for all-zeroes minimum values to prove ranges above
				commit_vec.as_ptr(),
				1,
				n_bits as size_t,
				value_gen_vec.as_ptr(),
				extra_data_vec.as_ptr(),
				extra_data_lengths.as_ptr(),
			);
			//			ffi::secp256k1_bulletproof_generators_destroy(self.ctx, gens);
			ffi::secp256k1_scratch_space_destroy(scratch);
			result == 1
		};

		if success {
			Ok(ProofRange {
				min: 0,
				max: u64::MAX,
			})
		} else {
			Err(Error::InvalidRangeProof)
		}
	}

	/// Rewind a bullet proof to get the value and Blinding factor back out
	pub fn rewind_bullet_proof(
		&self,
		commit: Commitment,
		nonce: SecretKey,
		extra_data_in: Option<Vec<u8>>,
		proof: RangeProof,
	) -> Result<ProofInfo, Error> {
		let (extra_data_len, extra_data) = match extra_data_in.as_ref() {
			Some(d) => (d.len(), d.as_ptr()),
			None => (0, ptr::null()),
		};

		let mut blind_out = [0u8; constants::SECRET_KEY_SIZE];
		let mut value_out = 0;
		let mut message_out = [0u8; 20];
		let commit = self.commit_parse(commit.0)?;

		let success = unsafe {
			let scratch = ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SPACE_SIZE);
			let result = ffi::secp256k1_bulletproof_rangeproof_rewind(
				self.ctx,
				&mut value_out,
				blind_out.as_mut_ptr(),
				proof.proof.as_ptr(),
				proof.plen as size_t,
				0,
				commit.as_ptr(),
				constants::GENERATOR_H.as_ptr(),
				nonce.as_ptr(),
				extra_data,
				extra_data_len as size_t,
				message_out.as_mut_ptr(),
			);
			//			ffi::secp256k1_bulletproof_generators_destroy(self.ctx, gens);
			ffi::secp256k1_scratch_space_destroy(scratch);
			result == 1
		};

		if success {
			Ok(ProofInfo {
				success: true,
				value: value_out,
				blinding: SecretKey(blind_out),
				message: ProofMessage::from_bytes(&message_out),
				mlen: 0,
				min: 0,
				max: u64::MAX,
				exp: 0,
				mantissa: 0,
			})
		} else {
			Err(Error::InvalidRangeProof)
		}
	}
}

#[cfg(test)]
mod tests {
	extern crate chrono;
	use super::{Commitment, Error, Message, ProofMessage, ProofRange, RangeProof, Secp256k1};
	use crate::key::{PublicKey, SecretKey, ONE_KEY, ZERO_KEY};
	use crate::ContextFlag;
	use crate::constants;

	use rand::{thread_rng, Rng};

	use crate::pedersen::tests::chrono::prelude::*;

	#[test]
	fn commit_parse_ser() {
		fn commit(value: u64) -> Commitment {
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			let blinding = ZERO_KEY;
			secp.commit(value, blinding).unwrap()
		}
		let two_g:[u8; 33] = [ 0x09,
			0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
			0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5
		];
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let commit_i = secp.commit_parse(two_g).unwrap();
		let comm = secp.commit_ser(commit_i.0).unwrap();
		assert_eq!(comm, Commitment(two_g));

		let c5 = commit(5);
		let commit_i = secp.commit_parse(c5.0).unwrap();
		let comm = secp.commit_ser(commit_i.0).unwrap();
		assert_eq!(comm, c5);

	}

	#[test]
	fn test_verify_commit_sum_zero_keys() {
		fn commit(value: u64) -> Commitment {
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			let blinding = ZERO_KEY;
			secp.commit(value, blinding).unwrap()
		}

		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		assert!(secp.verify_commit_sum(vec![], vec![],));

		assert!(secp.verify_commit_sum(vec![commit(5)], vec![commit(5)],));

		assert!(secp.verify_commit_sum(vec![commit(3), commit(2)], vec![commit(5)]));

		assert!(secp.verify_commit_sum(vec![commit(2), commit(4)], vec![commit(1), commit(5)]));
	}

	#[test]
	fn test_verify_commit_sum_one_keys() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		fn commit(value: u64, blinding: SecretKey) -> Commitment {
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			secp.commit(value, blinding).unwrap()
		}

		assert!(secp.verify_commit_sum(vec![commit(5, ONE_KEY)], vec![commit(5, ONE_KEY)]));

		// we expect this not to verify
		// even though the values add up to 0
		// the keys themselves do not add to 0
		assert_eq!(
			secp.verify_commit_sum(
				vec![commit(3, ONE_KEY), commit(2, ONE_KEY)],
				vec![commit(5, ONE_KEY)],
			),
			false
		);

		// to get these to verify we need to
		// use the same "sum" of blinding factors on both sides
		let two_key = secp.blind_sum(vec![ONE_KEY, ONE_KEY], vec![]).unwrap();
		assert!(secp.verify_commit_sum(
			vec![commit(3, ONE_KEY), commit(2, ONE_KEY)],
			vec![commit(5, two_key)],
		));
	}

	#[test]
	fn test_verify_commit_sum_random_keys() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		fn commit(value: u64, blinding: SecretKey) -> Commitment {
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			secp.commit(value, blinding).unwrap()
		}

		let blind_pos = SecretKey::new(&secp, &mut thread_rng());
		let blind_neg = SecretKey::new(&secp, &mut thread_rng());

		// now construct blinding factor to net out appropriately
		let blind_sum = secp.blind_sum(vec![blind_pos.clone()], vec![blind_neg.clone()]).unwrap();

		assert!(secp.verify_commit_sum(
			vec![commit(101, blind_pos)],
			vec![commit(75, blind_neg), commit(26, blind_sum)],
		));
	}

	#[test]
	fn test_verify_commit_sum_random_keys_switch() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		fn commit(value: u64, blinding: SecretKey) -> Commitment {
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			secp.commit(value, blinding).unwrap()
		}

		let pos_value = 101;
		let neg_value = 75;

		let blind_pos = secp.blind_switch(pos_value, SecretKey::new(&secp, &mut thread_rng())).unwrap();
		let blind_neg = secp.blind_switch(neg_value, SecretKey::new(&secp, &mut thread_rng())).unwrap();

		// now construct blinding factor to net out appropriately
		let blind_sum = secp.blind_sum(vec![blind_pos.clone()], vec![blind_neg.clone()]).unwrap();
		let diff = pos_value - neg_value;

		assert!(secp.verify_commit_sum(
			vec![commit(pos_value, blind_pos)],
			vec![commit(neg_value, blind_neg), commit(diff, blind_sum)],
		));
	}

	#[test]
	// to_pubkey() is not currently working as secp does currently
	// provide an api to extract a public key from a commitment
	fn test_to_pubkey() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let commit = secp.commit(5, blinding).unwrap();
		let pubkey = commit.to_pubkey(&secp);
		match pubkey {
			Ok(_) => {
				// this is good
			}
			Err(_) => {
				panic!("this is not good");
			}
		}
	}

	#[test]
	fn test_from_pubkey() {
		for _ in 0..100 {
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			let blinding = SecretKey::new(&secp, &mut thread_rng());
			let commit = secp.commit(1, blinding).unwrap();
			let pubkey = commit.to_pubkey(&secp);
			let p = match pubkey {
				Ok(p) => {
					// this is good
					p
				}
				Err(e) => {
					panic!("Creating pubkey: {}", e);
				}
			};
			//println!("Pre Commit is: {:?}", commit);
			//println!("Pre Pubkey is: {:?}", p);
			let new_commit = Commitment::from_pubkey(&secp, &p);
			let commit2 = match new_commit {
				Ok(c) => {
					// this is good
					c
				}
				Err(e) => {
					panic!("Creating commit from Pubkey: {}", e);
				}
			};
			//println!("Post Commit is: {:?}", commit2);
			//println!("Post Pubkey is: {:?}", p);
			assert_eq!(commit, commit2);
		}
	}

	#[test]
	fn test_sign_with_pubkey_from_commitment() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let commit = secp.commit(0u64, blinding.clone()).unwrap();

		let mut msg = [0u8; 32];
		thread_rng().fill(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();

		let sig = secp.sign(&msg, &blinding).unwrap();

		let pubkey = commit.to_pubkey(&secp).unwrap();

		// check that we can successfully verify the signature with the public key
		if let Ok(_) = secp.verify(&msg, &sig, &pubkey) {
			// this is good
		} else {
			panic!("this is not good");
		}
	}

	#[test]
	fn test_commit_sum() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		fn commit(value: u64, blinding: SecretKey) -> Commitment {
			let secp = Secp256k1::with_caps(ContextFlag::Commit);
			secp.commit(value, blinding).unwrap()
		}

		let blind_a = SecretKey::new(&secp, &mut thread_rng());
		let blind_b = SecretKey::new(&secp, &mut thread_rng());

		let commit_a = commit(3, blind_a.clone());
		let commit_b = commit(2, blind_b.clone());

		let blind_c = secp.blind_sum(vec![blind_a.clone(), blind_b.clone()], vec![]).unwrap();

		let commit_c = commit(3 + 2, blind_c);

		let commit_d = secp.commit_sum(vec![commit_a.clone(), commit_b.clone()], vec![]).unwrap();
		assert_eq!(commit_c, commit_d);

		let blind_e = secp.blind_sum(vec![blind_a.clone()], vec![blind_b.clone()]).unwrap();

		let commit_e = commit(3 - 2, blind_e);

		let commit_f = secp.commit_sum(vec![commit_a], vec![commit_b]).unwrap();
		assert_eq!(commit_e, commit_f);
	}

	#[test]
	fn test_blind_commit() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let rng = &mut thread_rng();
		let value: u64 = 1;
		let blind = SecretKey::new(&secp, rng);
		let blind2 = ONE_KEY;
		assert_eq!(secp.commit(value, blind.clone()).unwrap(), secp.commit_blind(blind2.clone(), blind.clone()).unwrap());
		let value: u64 = 2;
		let blind = SecretKey::new(&secp, rng);
		assert_ne!(secp.commit(value, blind.clone()).unwrap(), secp.commit_blind(blind2, blind.clone()).unwrap());
		let blind = SecretKey::new(&secp, rng);
		let mut blind2 = ZERO_KEY;
		blind2.0[30] = rng.gen::<u8>();
		blind2.0[31] = rng.gen::<u8>();
		let value: u64 = blind2[30] as u64*256 + blind2[31] as u64;
		assert_eq!(secp.commit(value, blind.clone()).unwrap(), secp.commit_blind(blind2, blind.clone()).unwrap());
	}

	#[test]
	fn test_range_proof() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let commit = secp.commit(7, blinding.clone()).unwrap();
		let msg = ProofMessage::empty();
		let range_proof = secp.range_proof(0, 7, blinding.clone(), commit, msg.clone());
		let proof_range = secp.verify_range_proof(commit, range_proof).unwrap();

		assert_eq!(proof_range.min, 0);

		let proof_info = secp.range_proof_info(range_proof);
		assert!(proof_info.success);
		assert_eq!(proof_info.min, 0);
		// check we get no information back for the value here
		assert_eq!(proof_info.value, 0);

		let proof_info = secp.rewind_range_proof(commit, range_proof, blinding.clone());
		assert!(proof_info.success);
		assert_eq!(proof_info.min, 0);
		assert_eq!(proof_info.value, 7);

		// check we cannot rewind a range proof without the original nonce
		let bad_nonce = SecretKey::new(&secp, &mut thread_rng());
		let bad_info = secp.rewind_range_proof(commit, range_proof, bad_nonce);
		assert_eq!(bad_info.success, false);
		assert_eq!(bad_info.value, 0);

		// check we can construct and verify a range proof on value 0
		let commit = secp.commit(0, blinding.clone()).unwrap();
		let range_proof = secp.range_proof(0, 0, blinding.clone(), commit, msg);
		secp.verify_range_proof(commit, range_proof).unwrap();
		let proof_info = secp.rewind_range_proof(commit, range_proof, blinding);
		assert!(proof_info.success);
		assert_eq!(proof_info.min, 0);
		assert_eq!(proof_info.value, 0);
	}

	#[test]
	fn test_bullet_proof_single() {
		// Test Bulletproofs without message
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let value = 12345678;
		let commit = secp.commit(value, blinding.clone()).unwrap();
		let bullet_proof = secp.bullet_proof(value, blinding.clone(), blinding.clone(), blinding.clone(), None, None);

		// correct verification
		println!("Bullet proof len: {}", bullet_proof.plen);
		let proof_range = secp
			.verify_bullet_proof(commit, bullet_proof, None)
			.unwrap();
		assert_eq!(proof_range.min, 0);

		// wrong value committed to
		let value = 12345678;
		let wrong_commit = secp.commit(87654321, blinding.clone()).unwrap();
		let bullet_proof = secp.bullet_proof(value, blinding.clone(), blinding.clone(), blinding.clone(), None, None);
		if !secp
			.verify_bullet_proof(wrong_commit, bullet_proof, None)
			.is_err()
		{
			panic!("Bullet proof verify should have errored");
		}

		// wrong blinding
		let value = 12345678;
		let commit = secp.commit(value, blinding).unwrap();
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let bullet_proof = secp.bullet_proof(value, blinding.clone(), blinding.clone(), blinding.clone(), None, None);
		if !secp
			.verify_bullet_proof(commit, bullet_proof, None)
			.is_err()
		{
			panic!("Bullet proof verify should have errored");
		}

		// Commit to some extra data in the bulletproof
		let extra_data = [0u8; 32].to_vec();
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let value = 12345678;
		let commit = secp.commit(value, blinding.clone()).unwrap();
		let bullet_proof =
			secp.bullet_proof(value, blinding.clone(), blinding.clone(), blinding.clone(), Some(extra_data.clone()), None);
		if secp
			.verify_bullet_proof(commit, bullet_proof, Some(extra_data.clone()))
			.is_err()
		{
			panic!("Bullet proof verify should NOT have errored.");
		}
		// Check verify fails without extra commit data
		let mut malleated_extra_data = [0u8; 32];
		malleated_extra_data[0] = 1;
		let res = secp.verify_bullet_proof(
			commit,
			bullet_proof,
			Some(malleated_extra_data.clone().to_vec()),
		);
		if !res.is_err() {
			panic!("Bullet proof verify should have errored: {:?}", res);
		}

		// Ensure rewinding works

		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let rewind_nonce = SecretKey::new(&secp, &mut thread_rng());
		let private_nonce = SecretKey::new(&secp, &mut thread_rng());
		let value = 12345678;
		let commit = secp.commit(value, blinding.clone()).unwrap();

		let bullet_proof =
			secp.bullet_proof(value, blinding.clone(), private_nonce.clone(), private_nonce.clone(), Some(extra_data.clone()), None);
		// Unwind message with same blinding factor
		let proof_info = secp
			.rewind_bullet_proof(commit, private_nonce.clone(), Some(extra_data.clone()), bullet_proof)
			.unwrap();
		assert_eq!(proof_info.value, value);
		assert_eq!(blinding, proof_info.blinding);

		// unwinding with wrong nonce data should puke
		let proof_info = secp.rewind_bullet_proof(
			commit,
			blinding.clone(),
			Some(extra_data.clone().to_vec()),
			bullet_proof,
		);
		if !proof_info.is_err() {
			panic!("Bullet proof verify with message should have errored.");
		}

		// unwinding with wrong extra data should puke
		let proof_info = secp.rewind_bullet_proof(commit, private_nonce.clone(), None, bullet_proof);
		if !proof_info.is_err() {
			panic!("Bullet proof verify with message should have errored.");
		}

		// Ensure including a message also works
		let message_bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
		let message = ProofMessage::from_bytes(&message_bytes);

		let bullet_proof = secp.bullet_proof(
			value,
			blinding.clone(),
			rewind_nonce.clone(),
			private_nonce.clone(),
			Some(extra_data.clone()),
			Some(message.clone()),
		);
		// Unwind message with same blinding factor
		let proof_info = secp
			.rewind_bullet_proof(commit, rewind_nonce, Some(extra_data.clone()), bullet_proof)
			.unwrap();
		assert_eq!(proof_info.value, value);
		assert_eq!(proof_info.message, message);
	}

	#[test]
	fn test_bullet_proof_multisig() {
		let multisig_bp =
			|v, nonce: SecretKey, ca, cb, ba, bb, msg, extra| -> (RangeProof, Result<ProofRange, Error>) {
				let secp = Secp256k1::with_caps(ContextFlag::Commit);
				let blinding_a: SecretKey = ba;
				let value: u64 = v;
				let partial_commit_a: Commitment = ca;

				let blinding_b: SecretKey = bb;
				let partial_commit_b: Commitment = cb;

				let message: Option<ProofMessage> = msg;
				let extra_data: Option<Vec<u8>> = extra;

				// upfront step: party A and party B generate self commitment and communicate to each other,
				//   to get the total commitment.
				let commit = secp
					.commit_sum(vec![partial_commit_a, partial_commit_b], vec![])
					.unwrap();
				let mut commits = vec![];
				commits.push(commit);

				let common_nonce = nonce;

				let private_nonce_a = SecretKey::new(&secp, &mut thread_rng());
				let private_nonce_b = SecretKey::new(&secp, &mut thread_rng());

				// 1st step on party A: generate t_one and t_two, and sends to party B
				let mut t_one_a = PublicKey::new();
				let mut t_two_a = PublicKey::new();
				secp.bullet_proof_multisig(
					value,
					blinding_a.clone(),
					common_nonce.clone(),
					extra_data.clone(),
					message.clone(),
					None,
					Some(&mut t_one_a),
					Some(&mut t_two_a),
					commits.clone(),
					Some(&private_nonce_a),
					1,
				);

				// 1st step on party B: generate t_one and t_two, and sends to party A
				let mut t_one_b = PublicKey::new();
				let mut t_two_b = PublicKey::new();
				secp.bullet_proof_multisig(
					value,
					blinding_b.clone(),
					common_nonce.clone(),
					extra_data.clone(),
					message.clone(),
					None,
					Some(&mut t_one_b),
					Some(&mut t_two_b),
					commits.clone(),
					Some(&private_nonce_b),
					1,
				);

				// 1st step on both party A and party B: sum up both t_one and both t_two.
				let mut pubkeys = vec![];
				pubkeys.push(&t_one_a);
				pubkeys.push(&t_one_b);
				let mut t_one_sum = PublicKey::from_combination(&secp, pubkeys.clone()).unwrap();

				pubkeys.clear();
				pubkeys.push(&t_two_a);
				pubkeys.push(&t_two_b);
				let mut t_two_sum = PublicKey::from_combination(&secp, pubkeys.clone()).unwrap();

				// 2nd step on party A: use t_one_sum and t_two_sum to generate tau_x, and sent to party B.
				let mut tau_x_a = SecretKey::new(&secp, &mut thread_rng());
				secp.bullet_proof_multisig(
					value,
					blinding_a.clone(),
					common_nonce.clone(),
					extra_data.clone(),
					message.clone(),
					Some(&mut tau_x_a),
					Some(&mut t_one_sum),
					Some(&mut t_two_sum),
					commits.clone(),
					Some(&private_nonce_a),
					2,
				);

				// 2nd step on party B: use t_one_sum and t_two_sum to generate tau_x, and send to party A.
				let mut tau_x_b = SecretKey::new(&secp, &mut thread_rng());
				secp.bullet_proof_multisig(
					value,
					blinding_b.clone(),
					common_nonce.clone(),
					extra_data.clone(),
					message.clone(),
					Some(&mut tau_x_b),
					Some(&mut t_one_sum),
					Some(&mut t_two_sum),
					commits.clone(),
					Some(&private_nonce_b),
					2,
				);

				// 2nd step on both party A and B: sum up both tau_x
				let mut tau_x_sum = tau_x_a;
				tau_x_sum.add_assign(&secp, &tau_x_b).unwrap();

				// 3rd step: party A finalizes bulletproof with input tau_x, t_one, t_two.
				let bullet_proof =
					secp.bullet_proof_multisig(
						value,
						blinding_a.clone(),
						common_nonce.clone(),
						extra_data.clone(),
						message.clone(),
						Some(&mut tau_x_sum),
						Some(&mut t_one_sum),
						Some(&mut t_two_sum),
						commits.clone(),
						Some(&private_nonce_a),
						0,
					).unwrap();

				// correct verification
				println!("MultiSig Bullet proof len: {:}", bullet_proof.len());
				let proof_range = secp.verify_bullet_proof(commit, bullet_proof, None);

				return (bullet_proof, proof_range);
			};

		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let value: u64 = 12345678;

		let common_nonce = SecretKey::new(&secp, &mut thread_rng());

		let blinding_a = SecretKey::new(&secp, &mut thread_rng());
		let partial_commit_a = secp.commit(value, blinding_a.clone()).unwrap();

		let blinding_b = SecretKey::new(&secp, &mut thread_rng());
		let partial_commit_b = secp.commit(0, blinding_b.clone()).unwrap();

		// 1. Test Bulletproofs multisig without message
		let (_, proof_range) = multisig_bp(
			value,
			common_nonce.clone(),
			partial_commit_a,
			partial_commit_b,
			blinding_a.clone(),
			blinding_b.clone(),
			None,
			None,
		);
		assert_eq!(proof_range.unwrap().min, 0);

		// 2. wrong value committed to
		let wrong_partial_commit_a = secp.commit(87654321, blinding_a.clone()).unwrap();
		let (_, proof_range) = multisig_bp(
			value,
			common_nonce.clone(),
			wrong_partial_commit_a,
			partial_commit_b,
			blinding_a.clone(),
			blinding_b.clone(),
			None,
			None,
		);
		if !proof_range.is_err() {
			panic!("Multi-Sig Bullet proof verify should have error");
		}

		// 3. wrong blinding
		let wrong_blinding = SecretKey::new(&secp, &mut thread_rng());
		let (_, proof_range) = multisig_bp(
			value,
			common_nonce.clone(),
			partial_commit_a,
			partial_commit_b,
			wrong_blinding,
			blinding_b.clone(),
			None,
			None,
		);
		if !proof_range.is_err() {
			panic!("Multi-Sig Bullet proof verify should have error");
		}

		// 4. Commit to a message in the bulletproof
		let message_bytes: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
		let message = ProofMessage::from_bytes(&message_bytes);
		let (_, proof_range) = multisig_bp(
			value,
			common_nonce,
			partial_commit_a,
			partial_commit_b,
			blinding_a,
			blinding_b,
			Some(message.clone()),
			None,
		);
		assert_eq!(proof_range.unwrap().min, 0);

		// Note: For the moment, Multi-Sig Bullet Proof implementation don't support rewind_bullet_proof().
		// TODO: uncomment the following test code when feature is ready.
		// Ensure rewinding works
		/*
		let mut extra_data = [0u8; 32];
		thread_rng().fill(&mut extra_data);

		let (bullet_proof, _) = multisig_bp(
			value,
			common_nonce,
			partial_commit_a,
			partial_commit_b,
			blinding_a,
			blinding_b,
			None,
			Some(extra_data.to_vec()),
		);
		// 5. Rewind message with same blinding factor
		let commit = secp
			.commit_sum(vec![partial_commit_a, partial_commit_b], vec![])
			.unwrap();
		let proof_info = secp.rewind_bullet_proof(
			commit,
			common_nonce.clone(),
			Some(extra_data.to_vec()),
			bullet_proof,
		);
		println!("proof_info after rewind: {:#?}", proof_info);

		let proof_info = proof_info.unwrap();
		assert_eq!(proof_info.value, value);

		let mut blinding = blinding_a;
		blinding.add_assign(&secp, &blinding_b).unwrap();
		assert_eq!(blinding, proof_info.blinding);

		// 6. Rewind with wrong nonce data should fail
		let proof_info = secp.rewind_bullet_proof(
			commit,
			blinding.clone(),
			Some(extra_data.to_vec()),
			bullet_proof,
		);
		if !proof_info.is_err() {
			panic!("Bullet proof verify with wrong nonce should have error.");
		}

		// 7. unwinding with wrong extra data should fail
		let proof_info = secp.rewind_bullet_proof(commit, common_nonce.clone(), None, bullet_proof);
		if !proof_info.is_err() {
			panic!("Bullet proof verify with wrong extra data should have error.");
		}

		// Ensure including a message also works
		let message_bytes: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
		let message = ProofMessage::from_bytes(&message_bytes);

		let (bullet_proof, _) = multisig_bp(
			value,
			common_nonce,
			partial_commit_a,
			partial_commit_b,
			blinding_a,
			blinding_b,
			Some(message.clone()),
			None,
		);
		// 8. Rewind message with same nonce
		let proof_info = secp
			.rewind_bullet_proof(
				commit,
				common_nonce.clone(),
				Some(extra_data.to_vec()),
				bullet_proof,
			).unwrap();
		assert_eq!(proof_info.message, message);
		*/	}

	#[test]
	fn rewind_empty_message() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let nonce = SecretKey::new(&secp, &mut thread_rng());
		let value = <u64>::max_value() - 1;
		let commit = secp.commit(value, blinding.clone()).unwrap();

		let mut pm = ProofMessage::from_bytes(&[0u8;32]);
		let bullet_proof = secp.bullet_proof(value, blinding.clone(), nonce.clone(), nonce.clone(), None, Some(pm.clone()));
		// Unwind message with same blinding factor
		let proof_info = secp
			.rewind_bullet_proof(commit, nonce, None, bullet_proof)
			.unwrap();
		assert_eq!(proof_info.value, value);
		assert_eq!(blinding, proof_info.blinding);
		pm.truncate(constants::BULLET_PROOF_MSG_SIZE);
		assert_eq!(pm, proof_info.message);
	}

	#[test]
	fn rewind_message() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let nonce = SecretKey::new(&secp, &mut thread_rng());
		let value = <u64>::max_value() - 1;
		let commit = secp.commit(value, blinding.clone()).unwrap();

		let bullet_proof = secp.bullet_proof(value, blinding.clone(), nonce.clone(), nonce.clone(), None, None);
		// Unwind message with same blinding factor
		let proof_info = secp
			.rewind_bullet_proof(commit, nonce.clone(), None, bullet_proof)
			.unwrap();
		assert_eq!(proof_info.value, value);
		assert_eq!(blinding, proof_info.blinding);

		// Using a different private nonce should prevent rewind of blinding factor
		let private_nonce = SecretKey::new(&secp, &mut thread_rng());
		let bullet_proof = secp.bullet_proof(value, blinding.clone(), nonce.clone(), private_nonce.clone(), None, None);
		let proof_info = secp
			.rewind_bullet_proof(commit, nonce, None, bullet_proof)
			.unwrap();
		assert_eq!(proof_info.value, value);
		assert_ne!(blinding, proof_info.blinding);
	}

	#[ignore]
	#[test]
	fn bench_bullet_proof_single_vs_multi() {
		let nano_to_millis = 1.0 / 1_000_000.0;

		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let value = 12345678;

		let increments = vec![1, 2, 5, 10, 100, 200];

		for v in increments {
			let mut commits: Vec<Commitment> = vec![];
			let mut proofs: Vec<RangeProof> = vec![];
			for i in 0..v {
				commits.push(secp.commit(value + i as u64, blinding.clone()).unwrap());
				proofs.push(secp.bullet_proof(value + i as u64, blinding.clone(), blinding.clone(), blinding.clone(), None, None));
			}
			println!("--------");
			println!("Comparing {} Proofs", v);
			let start = Utc::now().timestamp_nanos();
			for i in 0..v {
				let proof_range = secp
					.verify_bullet_proof(commits[i].clone(), proofs[i].clone(), None)
					.unwrap();
				assert_eq!(proof_range.min, 0);
			}
			let fin = Utc::now().timestamp_nanos();
			let dur_ms = (fin - start) as f64 * nano_to_millis;
			println!("{} proofs single validated in {}ms", v, dur_ms);

			let start = Utc::now().timestamp_nanos();
			let proof_range = secp.verify_bullet_proof_multi(commits.clone(), proofs.clone(), None);
			assert!(!proof_range.is_err());
			let fin = Utc::now().timestamp_nanos();
			let dur_ms = (fin - start) as f64 * nano_to_millis;
			println!("{} proofs batch validated in {}ms", v, dur_ms);
		}
	}

	#[test]
	fn test_bullet_proof_verify_multi() {
		let mut commits: Vec<Commitment> = vec![];
		let mut proofs: Vec<RangeProof> = vec![];

		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut thread_rng());
		let rewind_nonce  = SecretKey::new(&secp, &mut thread_rng());
		let private_nonce = SecretKey::new(&secp, &mut thread_rng());
		let wrong_blinding = SecretKey::new(&secp, &mut thread_rng());
		let value = 12345678;

		let wrong_commit = secp.commit(value, wrong_blinding).unwrap();

		commits.push(secp.commit(value, blinding.clone()).unwrap());
		proofs.push(secp.bullet_proof(value, blinding.clone(), rewind_nonce.clone(), private_nonce.clone(), None, None));
		let proof_range = secp
			.verify_bullet_proof(commits[0].clone(), proofs[0].clone(), None)
			.unwrap();
		assert_eq!(proof_range.min, 0);

		// verify with single element in each
		let proof_range = secp
			.verify_bullet_proof_multi(commits.clone(), proofs.clone(), None)
			.unwrap();
		assert_eq!(proof_range.min, 0);

		// verify wrong proof
		commits[0] = wrong_commit.clone();
		if !secp
			.verify_bullet_proof_multi(commits.clone(), proofs.clone(), None)
			.is_err()
		{
			panic!("Bullet proof multi verify should have errored.");
		}

		//  batching verification on double elements w/t extra message data
		commits = vec![];
		proofs = vec![];
		commits.push(secp.commit(value + 1, blinding.clone()).unwrap());
		commits.push(secp.commit(value - 1, blinding.clone()).unwrap());
		proofs.push(secp.bullet_proof(value + 1, blinding.clone(), rewind_nonce.clone(), private_nonce.clone(), None, None));
		proofs.push(secp.bullet_proof(value - 1, blinding.clone(), rewind_nonce.clone(), private_nonce.clone(), None, None));
		let proof_range = secp
			.verify_bullet_proof_multi(commits.clone(), proofs.clone(), None)
			.unwrap();
		assert_eq!(proof_range.min, 0);

		//  batching verification on double elements w/ extra message data
		let mut extra_data1 = [0u8; 64].to_vec();
		extra_data1[0] = 100;
		let mut extra_data2 = [0u8; 64].to_vec();
		extra_data2[0] = 200;

		proofs = vec![];
		proofs.push(secp.bullet_proof(
			value + 1,
			blinding.clone(),
			rewind_nonce.clone(),
			private_nonce.clone(),
			Some(extra_data1.clone()),
			None,
		));
		proofs.push(secp.bullet_proof(
			value - 1,
			blinding.clone(),
			rewind_nonce.clone(),
			private_nonce.clone(),
			Some(extra_data2.clone()),
			None,
		));

		let mut extra_data = vec![];
		extra_data.push(extra_data1.clone());
		extra_data.push(extra_data2.clone());
		let proof_range = secp
			.verify_bullet_proof_multi(commits.clone(), proofs.clone(), Some(extra_data.clone()))
			.unwrap();
		assert_eq!(proof_range.min, 0);

		// verify wrong extra message
		let mut extra_data = vec![];
		extra_data1[0] = 101; // simulate a wrong extra message
		extra_data.push(extra_data1.clone());
		extra_data.push(extra_data2.clone());
		if !secp
			.verify_bullet_proof_multi(commits.clone(), proofs.clone(), Some(extra_data.clone()))
			.is_err()
		{
			panic!("Bullet proof multi verify should have error.");
		}

		//  batching verification on 1-100 elements w/o extra message data
		commits = vec![];
		proofs = vec![];
		let mut errs = 0;
		for i in 1..100 {
			print!("\r\r\r{}", i);
			commits.push(secp.commit(value + i as u64, blinding.clone()).unwrap());
			proofs.push(secp.bullet_proof(value + i as u64, blinding.clone(), rewind_nonce.clone(), private_nonce.clone(), None, None));
			let proof_range = secp.verify_bullet_proof_multi(commits.clone(), proofs.clone(), None); //.unwrap();
			if proof_range.is_err() {
				println!(" proofs batch verify failed");
				errs += 1;
			}
		}
		assert_eq!(errs, 0);
	}
}

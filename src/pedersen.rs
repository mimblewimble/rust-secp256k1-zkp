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

//! # Pedersen commitments and related range proofs

use std::cmp::min;
use std::fmt;
use std::mem;
use libc::size_t;

use ContextFlag;
use Error;
use Secp256k1;

use constants;
use ffi;
use key;
use key::SecretKey;
use super::{Message, Signature};
use rand::{Rng, OsRng};
use serde::{ser, de};

/// A Pedersen commitment
pub struct Commitment(pub [u8; constants::PEDERSEN_COMMITMENT_SIZE]);
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
		mem::uninitialized()
	}

	/// Converts a commitment into two "candidate" public keys
	/// one of these will be valid, the other has the incorrect parity
	/// we just don't know which is which...
	/// once secp provides the necessary api we will no longer need this hack
	/// grin uses the public key to verify signatures (hopefully one of these keys works)
	fn to_two_pubkeys(&self, secp: &Secp256k1) -> [key::PublicKey; 2] {
		let mut pk1 = [0; constants::COMPRESSED_PUBLIC_KEY_SIZE];
		for i in 0..self.0.len() {
			if i == 0 {
				pk1[i] = 0x02;
			} else {
				pk1[i] = self.0[i];
			}
		}
		// TODO - we should not unwrap these here, and handle errors better
		let public_key1 = key::PublicKey::from_slice(secp, &pk1).unwrap();

		let mut pk2 = [0; constants::COMPRESSED_PUBLIC_KEY_SIZE];
		for i in 0..self.0.len() {
			if i == 0 {
				pk2[i] = 0x03;
			} else {
				pk2[i] = self.0[i];
			}
		}
		let public_key2 = key::PublicKey::from_slice(secp, &pk2).unwrap();
		[public_key1, public_key2]
	}

	/// Converts a commitment to a public key
	/// TODO - we need an API in secp to convert commitments to public keys safely
	/// a commitment is prefixed 08/09 and public keys are prefixed 02/03
	/// see to_two_pubkeys() for a short term workaround
	pub fn to_pubkey(&self, secp: &Secp256k1) -> Result<key::PublicKey, Error> {
		key::PublicKey::from_slice(secp, &self.0)
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
			use std::intrinsics::copy_nonoverlapping;
			use std::mem;
			let mut ret: [u8; constants::MAX_PROOF_SIZE] = mem::uninitialized();
			copy_nonoverlapping(self.proof.as_ptr(),
			                    ret.as_mut_ptr(),
			                    mem::size_of::<RangeProof>());
			RangeProof {
				proof: ret,
				plen: self.plen,
			}
		}
	}
}

impl ser::Serialize for RangeProof {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
		where S: ser::Serializer
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
		where V: de::SeqAccess<'di>
	{
		unsafe {
			use std::mem;
			let mut ret: [u8; constants::MAX_PROOF_SIZE] = mem::uninitialized();
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
		where D: de::Deserializer<'de>
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
}

impl ::std::cmp::PartialEq for ProofMessage {
	fn eq(&self, other: &ProofMessage) -> bool {
		self.0[..] == other.0[..]
	}
}
impl ::std::cmp::Eq for ProofMessage {}

impl ::std::fmt::Debug for ProofMessage {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		try!(write!(f, "{}(", stringify!(ProofMessage)));
		for i in self.0.iter().cloned() {
			try!(write!(f, "{:02x}", i));
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
		try!(write!(f, "{}(", stringify!(RangeProof)));
		for i in self.proof[..self.plen].iter().cloned() {
			try!(write!(f, "{:02x}", i));
		}
		write!(f, ")[{}]", self.plen)
	}
}

impl Secp256k1 {
	/// *** This is a temporary work-around. ***
	/// We do not know which of the two possible public keys from the commit to use,
	/// so here we try both of them and succeed if either works.
	/// This is sub-optimal in terms of performance.
	/// I believe apoelstra has a strategy for fixing this in the secp256k1-zkp lib.
	pub fn verify_from_commit(&self, msg: &Message, sig: &Signature, commit: &Commitment) -> Result<(), Error> {
		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}

		// If we knew which one we cared about here we would just use it,
		// but for now return both so we can try them both.
		let pubkeys = commit.to_two_pubkeys(&self);

		// Attempt to verify with the first public key,
		// if verify fails try the other one.
		// The first will fail on average 50% of the time.
		let result = self.verify(msg, sig, &pubkeys[0]);
		match result {
			Ok(x) => Ok(x),
			Err(_) => {
				self.verify(msg, sig, &pubkeys[1])
			}
		}
	}

	/// Creates a switch commitment from a blinding factor.
	pub fn switch_commit(&self,  blind: SecretKey) -> Result<Commitment, Error> {

		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}
		let mut commit = [0; 33];
		unsafe {
			ffi::secp256k1_switch_commit(self.ctx, commit.as_mut_ptr(), blind.as_ptr(), constants::GENERATOR_J.as_ptr());
		};
		Ok(Commitment(commit))
	}

	/// Creates a pedersen commitment from a value and a blinding factor
	pub fn commit(&self, value: u64, blind: SecretKey) -> Result<Commitment, Error> {

		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}
		let mut commit = [0; 33];

		unsafe {
			ffi::secp256k1_pedersen_commit(
				self.ctx,
				commit.as_mut_ptr(),
				blind.as_ptr(),
				value,
				constants::GENERATOR_H.as_ptr(),
			)};
		Ok(Commitment(commit))
	}

	/// Convenience method to Create a pedersen commitment only from a value,
	/// with a zero blinding factor
	pub fn commit_value(&self, value: u64) -> Result<Commitment, Error> {

		if self.caps != ContextFlag::Commit {
			return Err(Error::IncapableContext);
		}
		let mut commit = [0; 33];
		let zblind = [0; 32];

		unsafe {
			ffi::secp256k1_pedersen_commit(
				self.ctx,
				commit.as_mut_ptr(),
				zblind.as_ptr(),
				value,
				constants::GENERATOR_H.as_ptr(),
			)};
		Ok(Commitment(commit))
	}

	/// Taking vectors of positive and negative commitments as well as an
	/// expected excess, verifies that it all sums to zero.
	pub fn verify_commit_sum(
		&self,
		positive: Vec<Commitment>,
		negative: Vec<Commitment>
	) -> bool {
		let pos = map_vec!(positive, |p| p.0.as_ptr());
		let neg = map_vec!(negative, |n| n.0.as_ptr());
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
		negative: Vec<Commitment>
	) -> Result<Commitment, Error> {
		let pos = map_vec!(positive, |p| p.0.as_ptr());
		let neg = map_vec!(negative, |n| n.0.as_ptr());
		let mut ret = unsafe { Commitment::blank() };
		let err = unsafe {
			ffi::secp256k1_pedersen_commit_sum(
				self.ctx,
				ret.as_mut_ptr(),
				pos.as_ptr(),
				pos.len() as size_t,
				neg.as_ptr(),
				neg.len() as size_t,
			)
		};
		if err == 1 {
			Ok(ret)
		} else {
			Err(Error::IncorrectCommitSum)
		}
	}

	/// Computes the sum of multiple positive and negative blinding factors.
	pub fn blind_sum(
		&self,
		positive: Vec<SecretKey>,
		negative: Vec<SecretKey>
	) -> Result<SecretKey, Error> {
		let mut neg = map_vec!(negative, |n| n.as_ptr());
		let mut all = map_vec!(positive, |p| p.as_ptr());
		all.append(&mut neg);
		let mut ret: [u8; 32] = unsafe { mem::uninitialized() };
		unsafe {
			assert_eq!(
				ffi::secp256k1_pedersen_blind_sum(
				self.ctx,
				ret.as_mut_ptr(),
				all.as_ptr(),
				all.len() as size_t,
				positive.len() as size_t,
			), 1);
		}
		// secp256k1 should never return an invalid private
		SecretKey::from_slice(self, &ret)
	}

	/// Convenience function for generating a random nonce for a range proof.
	/// We will need the nonce later if we want to rewind the range proof.
	pub fn nonce(&self) -> [u8; 32] {
	    let mut rng = OsRng::new().unwrap();
	    let mut nonce = [0u8; 32];
	    rng.fill_bytes(&mut nonce);
	    nonce
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
		proof: RangeProof
	) -> Result<ProofRange, Error> {
		let mut min: u64 = 0;
		let mut max: u64 = 0;

		let extra_commit = [0u8; 33];

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
			Ok(ProofRange {
				min: min,
				max: max,
			})
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
		let mut blind: [u8; 32] = unsafe { mem::uninitialized() };
		let mut message: [u8; constants::PROOF_MSG_SIZE] = unsafe { mem::uninitialized() };
		let mut mlen: usize = constants::PROOF_MSG_SIZE;
		let mut min: u64 = 0;
		let mut max: u64 = 0;

		let extra_commit = [0u8; 33];

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

		let extra_commit = [0u8; 33];

		let success = unsafe {
			ffi::secp256k1_rangeproof_info(
				self.ctx,
				&mut exp,
				&mut mantissa,
				&mut min,
				&mut max,
				proof.proof.as_ptr(),
				proof.plen as size_t,
				extra_commit.as_ptr(),
				0 as size_t,
				constants::GENERATOR_H.as_ptr(),
			) == 1
		};
		ProofInfo {
			success: success,
			value: 0,
			message: ProofMessage::empty(),
			mlen: 0,
			min: min,
			max: max,
			exp: exp,
			mantissa: mantissa,
		}
	}
}

#[cfg(test)]
mod tests {
    use super::{Commitment, ProofMessage, Message, Secp256k1};
    use ContextFlag;
    use key::{ONE_KEY, ZERO_KEY, SecretKey};

    use rand::os::OsRng;
	use rand::{Rng, thread_rng};


    #[test]
    fn test_verify_commit_sum_zero_keys() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            let blinding = ZERO_KEY;
            secp.commit(value, blinding).unwrap()
        }

        assert!(secp.verify_commit_sum(
            vec![],
            vec![],
        ));

        assert!(secp.verify_commit_sum(
            vec![commit(5)],
            vec![commit(5)],
        ));

        assert!(secp.verify_commit_sum(
            vec![commit(3), commit(2)],
            vec![commit(5)],
        ));

        assert!(secp.verify_commit_sum(
            vec![commit(2), commit(4)],
            vec![commit(1), commit(5)],
        ));
    }

    #[test]
    fn test_verify_commit_sum_one_keys() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        fn commit(value: u64, blinding: SecretKey) -> Commitment {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            secp.commit(value, blinding).unwrap()

        }

        assert!(secp.verify_commit_sum(
            vec![commit(5, ONE_KEY)],
            vec![commit(5, ONE_KEY)],
        ));

        // we expect this not to verify
        // even though the values add up to 0
        // the keys themselves do not add to 0
        assert_eq!(secp.verify_commit_sum(
            vec![commit(3, ONE_KEY), commit(2, ONE_KEY)],
            vec![commit(5, ONE_KEY)],
        ), false);

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

        let blind_pos = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let blind_neg = SecretKey::new(&secp, &mut OsRng::new().unwrap());

        // now construct blinding factor to net out appropriately
        let blind_sum = secp.blind_sum(vec![blind_pos], vec![blind_neg]).unwrap();

        assert!(secp.verify_commit_sum(
            vec![commit(101, blind_pos)],
            vec![commit(75, blind_neg), commit(26, blind_sum)],
        ));
    }

	#[test]
	fn test_to_two_pubkeys() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
		let commit = secp.commit(5, blinding).unwrap();
		assert_eq!(commit.to_two_pubkeys(&secp).len(), 2);
	}

	#[test]
	// to_pubkey() is not currently working as secp does currently
	// provide an api to extract a public key from a commitment
	fn test_to_pubkey() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
		let commit = secp.commit(5, blinding).unwrap();
		let pubkey = commit.to_pubkey(&secp);
		match pubkey {
			Ok(_) => panic!("expected this to return an error"),
			Err(_) => {}
		}
	}

	#[test]
	fn test_sign_with_pubkey_from_commitment() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
		let commit = secp.commit(0u64, blinding).unwrap();

		let mut msg = [0u8; 32];
		thread_rng().fill_bytes(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();

		let sig = secp.sign(&msg, &blinding).unwrap();

		let pubkeys = commit.to_two_pubkeys(&secp);

		// check that we can successfully verify the signature with one of the public keys
		if let Ok(_) = secp.verify(&msg, &sig, &pubkeys[0]) {
			// this is good
		} else if let Ok(_) = secp.verify(&msg, &sig, &pubkeys[1]) {
			// this is also good
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

		let blind_a = SecretKey::new(&secp, &mut OsRng::new().unwrap());
		let blind_b = SecretKey::new(&secp, &mut OsRng::new().unwrap());

		let commit_a = commit(3, blind_a);
		let commit_b = commit(2, blind_b);

		let blind_c = secp.blind_sum(vec![blind_a, blind_b], vec![]).unwrap();

		let commit_c = commit(3 + 2, blind_c);

		let commit_d = secp.commit_sum(vec![commit_a, commit_b], vec![]).unwrap();
		assert_eq!(commit_c, commit_d);

		let blind_e = secp.blind_sum(vec![blind_a], vec![blind_b]).unwrap();

		let commit_e = commit(3 - 2, blind_e);

		let commit_f = secp.commit_sum(vec![commit_a], vec![commit_b]).unwrap();
		assert_eq!(commit_e, commit_f);
	}

	#[test]
	fn test_range_proof() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let blinding = SecretKey::new(&secp, &mut OsRng::new().unwrap());
		let commit = secp.commit(7, blinding).unwrap();
		let msg = ProofMessage::empty();
		let range_proof = secp.range_proof(0, 7, blinding, commit, msg.clone());
		let proof_range = secp.verify_range_proof(commit, range_proof).unwrap();

		assert_eq!(proof_range.min, 0);

		let proof_info = secp.range_proof_info(range_proof);
		assert!(proof_info.success);
		assert_eq!(proof_info.min, 0);
		// check we get no information back for the value here
		assert_eq!(proof_info.value, 0);

		let proof_info = secp.rewind_range_proof(commit, range_proof, blinding);
		assert!(proof_info.success);
		assert_eq!(proof_info.min, 0);
		assert_eq!(proof_info.value, 7);

		// check we cannot rewind a range proof without the original nonce
		let bad_nonce = SecretKey::new(&secp, &mut OsRng::new().unwrap());
		let bad_info = secp.rewind_range_proof(commit, range_proof, bad_nonce);
		assert_eq!(bad_info.success, false);
		assert_eq!(bad_info.value, 0);

		// check we can construct and verify a range proof on value 0
		let commit = secp.commit(0, blinding).unwrap();
		let range_proof = secp.range_proof(0, 0, blinding, commit, msg);
		secp.verify_range_proof(commit, range_proof).unwrap();
		let proof_info = secp.rewind_range_proof(commit, range_proof, blinding.clone());
		assert!(proof_info.success);
		assert_eq!(proof_info.min, 0);
		assert_eq!(proof_info.value, 0);
	}
}

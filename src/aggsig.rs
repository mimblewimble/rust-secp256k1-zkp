// Rust secp256k1 bindings for aggsig functions
// 2018 The Grin developers
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

//! # Aggregated Signature (a.k.a. Schnorr) Functionality

use libc::size_t;
use crate::ffi;
use crate::key::{PublicKey, SecretKey};
use rand::{thread_rng, Rng};
use std::ptr;
use crate::Secp256k1;
use crate::{AggSigPartialSignature, Error, Message, Signature};

const SCRATCH_SPACE_SIZE: size_t = 1024 * 1024;

/// The 256 bits 0
pub const ZERO_256: [u8; 32] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Single-Signer (plain old Schnorr, sans-multisig) export nonce
/// Returns: Ok(SecretKey) on success
/// In:
/// msg: the message to sign
/// seckey: the secret key
pub fn export_secnonce_single(secp: &Secp256k1) -> Result<SecretKey, Error> {
	let mut return_key = SecretKey::new(&secp, &mut thread_rng());
	let mut seed = [0u8; 32];
	thread_rng().fill(&mut seed);
	let retval = unsafe {
		ffi::secp256k1_aggsig_export_secnonce_single(
			secp.ctx,
			return_key.as_mut_ptr(),
			seed.as_ptr(),
		)
	};
	if retval == 0 {
		return Err(Error::InvalidSignature);
	}
	Ok(return_key)
}

// This is a macro that check zero public key
macro_rules! is_zero_pubkey {
	(reterr => $e:expr) => {
		match $e {
			Some(n) => {
				if (n.0).0.starts_with(&ZERO_256) {
					return Err(Error::InvalidPublicKey);
					}
				n.as_ptr()
				}
			None => ptr::null(),
			}
	};
	(retfalse => $e:expr) => {
		match $e {
			Some(n) => {
				if (n.0).0.starts_with(&ZERO_256) {
					return false;
					}
				n.as_ptr()
				}
			None => ptr::null(),
			}
	};
}

/// Single-Signer (plain old Schnorr, sans-multisig) signature creation
/// Returns: Ok(Signature) on success
/// In:
/// msg: the message to sign
/// seckey: the secret key
/// extra: if Some(), add this key to s
/// secnonce: if Some(SecretKey), the secret nonce to use. If None, generate a nonce
/// pubnonce: if Some(PublicKey), overrides the public nonce to encode as part of e
/// final_nonce_sum: if Some(PublicKey), overrides the public nonce to encode as part of e
pub fn sign_single(
	secp: &Secp256k1,
	msg: &Message,
	seckey: &SecretKey,
	secnonce: Option<&SecretKey>,
	extra: Option<&SecretKey>,
	pubnonce: Option<&PublicKey>,
	pubkey_for_e: Option<&PublicKey>,
	final_nonce_sum: Option<&PublicKey>,
) -> Result<Signature, Error> {
	let mut retsig = Signature::from(ffi::Signature::new());
	let mut seed = [0u8; 32];
	thread_rng().fill(&mut seed);

	let secnonce = match secnonce {
		Some(n) => n.as_ptr(),
		None => ptr::null(),
	};

	let pubnonce = is_zero_pubkey!(reterr => pubnonce);

	let extra = match extra {
		Some(e) => e.as_ptr(),
		None => ptr::null(),
	};

	let final_nonce_sum = is_zero_pubkey!(reterr => final_nonce_sum);

	let pe = is_zero_pubkey!(reterr => pubkey_for_e);

	let retval = unsafe {
		ffi::secp256k1_aggsig_sign_single(
			secp.ctx,
			retsig.as_mut_ptr(),
			msg.as_ptr(),
			seckey.as_ptr(),
			secnonce,
			extra,
			pubnonce,
			final_nonce_sum,
			pe,
			seed.as_ptr(),
		)
	};
	if retval == 0 {
		return Err(Error::InvalidSignature);
	}
	Ok(retsig)
}

/// Single-Signer (plain old Schnorr, sans-multisig) signature verification
/// Returns: Ok(Signature) on success
/// In:
/// sig: The signature
/// msg: the message to verify
/// pubnonce: if Some(PublicKey) overrides the public nonce used to calculate e
/// pubkey: the public key
/// pubkey_total: The total of all public keys (for the message in e)
/// is_partial: whether this is a partial sig, or a fully-combined sig
pub fn verify_single(
	secp: &Secp256k1,
	sig: &Signature,
	msg: &Message,
	pubnonce: Option<&PublicKey>,
	pubkey: &PublicKey,
	pubkey_total_for_e: Option<&PublicKey>,
	extra_pubkey: Option<&PublicKey>,
	is_partial: bool,
) -> bool {
	let pubnonce = is_zero_pubkey!(retfalse => pubnonce);

	let pe = is_zero_pubkey!(retfalse => pubkey_total_for_e);

	let extra = is_zero_pubkey!(retfalse => extra_pubkey);

	let is_partial = match is_partial {
		true => 1,
		false => 0,
	};

	if (sig.0).0.starts_with(&ZERO_256) || (pubkey.0).0.starts_with(&ZERO_256) {
		return false;
	}

	let retval = unsafe {
		ffi::secp256k1_aggsig_verify_single(
			secp.ctx,
			sig.as_ptr(),
			msg.as_ptr(),
			pubnonce,
			pubkey.as_ptr(),
			pe,
			extra,
			is_partial,
		)
	};
	match retval {
		0 => false,
		1 => true,
		_ => false,
	}
}


/// Batch Schnorr signature verification
/// Returns: true on success
/// In:
/// sigs: The signatures
/// msg: The messages to verify
/// pubkey: The public keys
pub fn verify_batch(
	secp: &Secp256k1,
	sigs: &Vec<Signature>,
	msgs: &Vec<Message>,
	pub_keys: &Vec<PublicKey>,
) -> bool {
	if sigs.len() != msgs.len() || sigs.len() != pub_keys.len() {
		return false;
	}

	for i in 0..pub_keys.len() {
		if (pub_keys[i].0).0.starts_with(&ZERO_256) {
			return false;
		}
	}

	let sigs_vec = map_vec!(sigs, |s| s.0.as_ptr());
	let msgs_vec = map_vec!(msgs, |m| m.as_ptr());
	let pub_keys_vec = map_vec!(pub_keys, |pk| pk.as_ptr());

	unsafe {
		let scratch = ffi::secp256k1_scratch_space_create(secp.ctx, SCRATCH_SPACE_SIZE);
		let result = ffi::secp256k1_schnorrsig_verify_batch(
			secp.ctx,
			scratch,
			sigs_vec.as_ptr(),
			msgs_vec.as_ptr(),
			pub_keys_vec.as_ptr(),
			sigs.len(),
		);
		ffi::secp256k1_scratch_space_destroy(scratch);
		result == 1
	}
}

/// Single-Signer addition of Signatures
/// Returns: Ok(Signature) on success
/// In:
/// sig1: sig1 to add
/// sig2: sig2 to add
/// pubnonce_total: sum of public nonces
pub fn add_signatures_single(
	secp: &Secp256k1,
	sigs: Vec<&Signature>,
	pubnonce_total: &PublicKey,
) -> Result<Signature, Error> {
	let mut retsig = Signature::from(ffi::Signature::new());
	let sig_vec = map_vec!(sigs, |s| s.0.as_ptr());
	let retval = unsafe {
		ffi::secp256k1_aggsig_add_signatures_single(
			secp.ctx,
			retsig.as_mut_ptr(),
			sig_vec.as_ptr(),
			sig_vec.len(),
			pubnonce_total.as_ptr(),
		)
	};
	if retval == 0 {
		return Err(Error::InvalidSignature);
	}
	Ok(retsig)
}

/// Manages an instance of an aggsig multisig context, and provides all methods
/// to act on that context
#[derive(Clone, Debug)]
pub struct AggSigContext {
	ctx: *mut ffi::Context,
	aggsig_ctx: *mut ffi::AggSigContext,
}

impl AggSigContext {
	/// Creates new aggsig context with a new random seed
	pub fn new(secp: &Secp256k1, pubkeys: &Vec<PublicKey>) -> AggSigContext {
		let mut seed = [0u8; 32];
		thread_rng().fill(&mut seed);
		let pubkeys: Vec<*const ffi::PublicKey> = pubkeys.into_iter().map(|p| p.as_ptr()).collect();
		let pubkeys = &pubkeys[..];
		unsafe {
			AggSigContext {
				ctx: secp.ctx,
				aggsig_ctx: ffi::secp256k1_aggsig_context_create(
					secp.ctx,
					pubkeys[0],
					pubkeys.len(),
					seed.as_ptr(),
				),
			}
		}
	}

	/// Generate a nonce pair for a single signature part in an aggregated signature
	/// Returns: true on success
	///          false if a nonce has already been generated for this index
	/// In: index: which signature to generate a nonce for
	pub fn generate_nonce(&self, index: usize) -> bool {
		let retval =
			unsafe { ffi::secp256k1_aggsig_generate_nonce(self.ctx, self.aggsig_ctx, index) };
		match retval {
			0 => false,
			1 => true,
			_ => false,
		}
	}

	/// Generate a single signature part in an aggregated signature
	/// Returns: Ok(AggSigPartialSignature) on success
	/// In:
	/// msg: the message to sign
	/// seckey: the secret key
	/// index: which index to generate a partial sig for
	pub fn partial_sign(
		&self,
		msg: Message,
		seckey: SecretKey,
		index: usize,
	) -> Result<AggSigPartialSignature, Error> {
		let mut retsig = AggSigPartialSignature::from(ffi::AggSigPartialSignature::new());
		let retval = unsafe {
			ffi::secp256k1_aggsig_partial_sign(
				self.ctx,
				self.aggsig_ctx,
				retsig.as_mut_ptr(),
				msg.as_ptr(),
				seckey.as_ptr(),
				index,
			)
		};
		if retval == 0 {
			return Err(Error::PartialSigFailure);
		}
		Ok(retsig)
	}

	/// Aggregate multiple signature parts into a single aggregated signature
	/// Returns: Ok(Signature) on success
	/// In:
	/// partial_sigs: vector of partial signatures
	pub fn combine_signatures(
		&self,
		partial_sigs: &Vec<AggSigPartialSignature>,
	) -> Result<Signature, Error> {
		let mut retsig = Signature::from(ffi::Signature::new());
		let partial_sigs: Vec<*const ffi::AggSigPartialSignature> =
			partial_sigs.into_iter().map(|p| p.as_ptr()).collect();
		let partial_sigs = &partial_sigs[..];
		let retval = unsafe {
			ffi::secp256k1_aggsig_combine_signatures(
				self.ctx,
				self.aggsig_ctx,
				retsig.as_mut_ptr(),
				partial_sigs[0],
				partial_sigs.len(),
			)
		};
		if retval == 0 {
			return Err(Error::PartialSigFailure);
		}
		Ok(retsig)
	}

	/// Verifies aggregate sig
	/// Returns: true if valid, okay if not
	/// In:
	/// msg: message to verify
	/// sig: combined signature
	/// pks: public keys
	pub fn verify(&self, sig: Signature, msg: Message, pks: &Vec<PublicKey>) -> bool {
		let pks: Vec<*const ffi::PublicKey> = pks.into_iter().map(|p| p.as_ptr()).collect();
		let pks = &pks[..];
		let retval = unsafe {
			ffi::secp256k1_aggsig_build_scratch_and_verify(
				self.ctx,
				sig.as_ptr(),
				msg.as_ptr(),
				pks[0],
				pks.len(),
			)
		};
		match retval {
			0 => false,
			1 => true,
			_ => false,
		}
	}
}

impl Drop for AggSigContext {
	fn drop(&mut self) {
		unsafe {
			ffi::secp256k1_aggsig_context_destroy(self.aggsig_ctx);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{
		add_signatures_single, export_secnonce_single, sign_single, verify_single, verify_batch,
		AggSigContext, Secp256k1,
	};
	use crate::ffi;
	use crate::key::{PublicKey, SecretKey};
	use rand::{thread_rng, Rng};
	use crate::ContextFlag;
	use crate::{AggSigPartialSignature, Message, Signature};

	#[test]
	fn test_aggsig_multisig() {
		let numkeys = 5;
		let secp = Secp256k1::with_caps(ContextFlag::Full);
		let mut keypairs: Vec<(SecretKey, PublicKey)> = vec![];
		for _ in 0..numkeys {
			keypairs.push(secp.generate_keypair(&mut thread_rng()).unwrap());
		}
		let pks: Vec<PublicKey> = keypairs.clone().into_iter().map(|(_, p)| p).collect();
		println!(
			"Creating aggsig context with {} pubkeys: {:?}",
			pks.len(),
			pks
		);
		let aggsig = AggSigContext::new(&secp, &pks);
		println!("Generating nonces for each index");
		for i in 0..numkeys {
			let retval = aggsig.generate_nonce(i);
			println!("{} returned {}", i, retval);
			assert!(retval == true);
		}

		let mut msg = [0u8; 32];
		thread_rng().fill(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();
		let mut partial_sigs: Vec<AggSigPartialSignature> = vec![];
		for i in 0..numkeys {
			println!(
				"Partial sign message: {:?} at index {}, SK:{:?}",
				msg, i, keypairs[i].0
			);

			let result = aggsig.partial_sign(msg, keypairs[i].0.clone(), i);
			match result {
				Ok(ps) => {
					println!("Partial sig: {:?}", ps);
					partial_sigs.push(ps);
				}
				Err(e) => panic!("Partial sig failed: {}", e),
			}
		}

		let result = aggsig.combine_signatures(&partial_sigs);

		let combined_sig = match result {
			Ok(cs) => {
				println!("Combined sig: {:?}", cs);
				cs
			}
			Err(e) => panic!("Combining partial sig failed: {}", e),
		};

		println!(
			"Verifying Combined sig: {:?}, msg: {:?}, pks:{:?}",
			combined_sig, msg, pks
		);
		let result = aggsig.verify(combined_sig, msg, &pks);
		println!("Signature verification: {}", result);
	}

	#[test]
	fn test_aggsig_single() {
		let secp = Secp256k1::with_caps(ContextFlag::Full);
		let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

		println!(
			"Performing aggsig single context with seckey, pubkey: {:?},{:?}",
			sk, pk
		);

		let mut msg = [0u8; 32];
		thread_rng().fill(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();
		let sig = sign_single(&secp, &msg, &sk, None, None, None, None, None).unwrap();

		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &pk, None, None, false);
		println!("Signature verification single (correct): {}", result);
		assert!(result == true);

		let mut msg = [0u8; 32];
		thread_rng().fill(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &pk, None, None, false);
		println!("Signature verification single (wrong message): {}", result);
		assert!(result == false);

		// test optional extra key
		let mut msg = [0u8; 32];
		thread_rng().fill(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();
		let (sk_extra, pk_extra) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let sig = sign_single(&secp, &msg, &sk, None, Some(&sk_extra), None, None, None).unwrap();
		let result = verify_single(&secp, &sig, &msg, None, &pk, None, Some(&pk_extra), false);
		assert!(result == true);
	}

	#[test]
	fn test_aggsig_batch() {
		let secp = Secp256k1::with_caps(ContextFlag::Full);

		let mut sigs: Vec<Signature> = vec![];
		let mut msgs: Vec<Message> = vec![];
		let mut pub_keys: Vec<PublicKey> = vec![];

		for _ in 0..100 {
			let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();
			let mut msg = [0u8; 32];
			thread_rng().fill(&mut msg);

			let msg = Message::from_slice(&msg).unwrap();
			let sig = sign_single(&secp, &msg, &sk, None, None, None, Some(&pk), None).unwrap();
			
			let result_single = verify_single(&secp, &sig, &msg, None, &pk, Some(&pk), None, false);
			assert!(result_single == true);
			
			pub_keys.push(pk);
			msgs.push(msg);
			sigs.push(sig);
		}

		println!("Verifying aggsig batch of 100");
		let result = verify_batch(&secp, &sigs, &msgs, &pub_keys);
		assert!(result == true);
	}

	#[test]
	fn test_aggsig_fuzz() {
		let secp = Secp256k1::with_caps(ContextFlag::Full);
		let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

		println!(
			"Performing aggsig single context with seckey, pubkey: {:?},{:?}",
			sk, pk
		);

		let mut msg = [0u8; 32];
		thread_rng().fill(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();
		let sig = sign_single(&secp, &msg, &sk, None, None, None, None, None).unwrap();

		// force sig[32..] as 0 to simulate Fuzz test
		let corrupted = &mut [0u8; 64];
		let mut i = 0;
		for elem in corrupted[..32].iter_mut() {
			*elem = sig.0[i];
			i += 1;
		}
		let corrupted_sig: Signature = Signature {
			0: ffi::Signature(*corrupted),
		};
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			corrupted_sig, msg, pk
		);
		let result = verify_single(&secp, &corrupted_sig, &msg, None, &pk, None, None, false);
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		// force sig[0..32] as 0 to simulate Fuzz test
		let corrupted = &mut [0u8; 64];
		let mut i = 32;
		for elem in corrupted[32..].iter_mut() {
			*elem = sig.0[i];
			i += 1;
		}
		let corrupted_sig: Signature = Signature {
			0: ffi::Signature(*corrupted),
		};
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			corrupted_sig, msg, pk
		);
		let result = verify_single(&secp, &corrupted_sig, &msg, None, &pk, None, None, false);
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		// force pk as 0 to simulate Fuzz test
		let zero_pk = PublicKey::new();
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, zero_pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &zero_pk, None, None, false);
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		let mut sigs: Vec<Signature> = vec![];
		sigs.push(sig);
		let mut msgs: Vec<Message> = vec![];
		msgs.push(msg);
		let mut pub_keys: Vec<PublicKey> = vec![];
		pub_keys.push(zero_pk);
		println!(
			"Verifying aggsig batch: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, zero_pk
		);
		let result = verify_batch(&secp, &sigs, &msgs, &pub_keys);
		println!("Signature verification batch: {}", result);
		assert!(result == false);


		// force pk[0..32] as 0 to simulate Fuzz test
		let corrupted = &mut [0u8; 64];
		let mut i = 32;
		for elem in corrupted[32..].iter_mut() {
			*elem = pk.0[i];
			i += 1;
		}
		let corrupted_pk: PublicKey = PublicKey {
			0: ffi::PublicKey(*corrupted),
		};
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, corrupted_pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &corrupted_pk, None, None, false);
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		// more tests on other parameters
		let zero_pk = PublicKey::new();
		let result = verify_single(
			&secp,
			&sig,
			&msg,
			Some(&zero_pk),
			&zero_pk,
			Some(&zero_pk),
			Some(&zero_pk),
			false,
		);
		assert!(result == false);

		let mut msg = [0u8; 32];
		thread_rng().fill(&mut msg);
		let msg = Message::from_slice(&msg).unwrap();
		if sign_single(
			&secp,
			&msg,
			&sk,
			None,
			None,
			Some(&zero_pk),
			Some(&zero_pk),
			Some(&zero_pk),
		).is_ok()
		{
			panic!("sign_single should fail on zero public key, but not!");
		}
	}

	#[test]
	fn test_aggsig_exchange() {
		for _ in 0..20 {
			let secp = Secp256k1::with_caps(ContextFlag::Full);
			// Generate keys for sender, receiver
			let (sk1, pk1) = secp.generate_keypair(&mut thread_rng()).unwrap();
			let (sk2, pk2) = secp.generate_keypair(&mut thread_rng()).unwrap();

			// Generate nonces for sender, receiver
			let secnonce_1 = export_secnonce_single(&secp).unwrap();
			let secnonce_2 = export_secnonce_single(&secp).unwrap();

			// Calculate public nonces
			let _ = PublicKey::from_secret_key(&secp, &secnonce_1).unwrap();
			let pubnonce_2 = PublicKey::from_secret_key(&secp, &secnonce_2).unwrap();

			// And get the total
			let mut nonce_sum = pubnonce_2.clone();
			let _ = nonce_sum.add_exp_assign(&secp, &secnonce_1);

			// Random message
			let mut msg = [0u8; 32];
			thread_rng().fill(&mut msg);
			let msg = Message::from_slice(&msg).unwrap();

			// Add public keys (for storing in e)
			let mut pk_sum = pk2.clone();
			let _ = pk_sum.add_exp_assign(&secp, &sk1);

			// Receiver signs
			let sig1 = sign_single(
				&secp,
				&msg,
				&sk1,
				Some(&secnonce_1),
				None,
				Some(&nonce_sum),
				Some(&pk_sum),
				Some(&nonce_sum),
			).unwrap();

			// Sender verifies receivers sig
			let result = verify_single(
				&secp,
				&sig1,
				&msg,
				Some(&nonce_sum),
				&pk1,
				Some(&pk_sum),
				None,
				true,
			);
			assert!(result == true);

			// Sender signs
			let sig2 = sign_single(
				&secp,
				&msg,
				&sk2,
				Some(&secnonce_2),
				None,
				Some(&nonce_sum),
				Some(&pk_sum),
				Some(&nonce_sum),
			).unwrap();

			// Receiver verifies sender's sig
			let result = verify_single(
				&secp,
				&sig2,
				&msg,
				Some(&nonce_sum),
				&pk2,
				Some(&pk_sum),
				None,
				true,
			);
			assert!(result == true);

			let sig_vec = vec![&sig1, &sig2];
			// Receiver calculates final sig
			let final_sig = add_signatures_single(&secp, sig_vec, &nonce_sum).unwrap();

			// Verification of final sig:
			let result = verify_single(
				&secp,
				&final_sig,
				&msg,
				None,
				&pk_sum,
				Some(&pk_sum),
				None,
				false,
			);
			assert!(result == true);
		}
	}
}

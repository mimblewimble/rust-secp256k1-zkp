// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
// 2017 The grin developers
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


use Secp256k1;
use ffi;
use rand::{Rng, thread_rng};
use {Message, Error, Signature, AggSigPartialSignature};
use key::{SecretKey, PublicKey};

/// Single-Signer (plain old Schnorr, sans-multisig) signature creation
/// Returns: Ok(Signature) on success
/// In: 
/// msg: the message to sign
/// seckey: the secret key
#[deprecated(since="0.1.0", note="underlying aggisg api still subject to review and change")]
pub fn sign_single(secp: &Secp256k1, msg:Message, seckey:SecretKey) ->
                    Result<Signature, Error> {
    let mut retsig = Signature::from(ffi::Signature::new());
    let mut seed = [0; 32];
    thread_rng().fill_bytes(&mut seed);
    let retval = unsafe {
        ffi::secp256k1_aggsig_sign_single(secp.ctx,
                                          retsig.as_mut_ptr(),
                                          msg.as_ptr(),
                                          seckey.as_ptr(),
                                          seed.as_ptr())
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
/// pubkey: the public key
#[deprecated(since="0.1.0", note="underlying aggisg api still subject to review and change")]
pub fn verify_single(secp: &Secp256k1, sig:Signature, msg:Message, pubkey:PublicKey) ->
                     bool {
    let retval = unsafe {
        ffi::secp256k1_aggsig_verify_single(secp.ctx,
                                            sig.as_ptr(),
                                            msg.as_ptr(),
                                            pubkey.as_ptr())
    };
    match retval {
        0 => false,
        1 => true,
        _ => false,
    }
}

/// Manages an instance of an aggsig multisig context, and provides all methods
/// to act on that context
#[derive(Clone, Debug)]
pub struct MultiSigContext {
    ctx: *mut ffi::Context,
    aggsig_ctx: *mut ffi::AggSigContext,
}

impl MultiSigContext {
    /// Creates new aggsig context with a new random seed
    #[deprecated(since="0.1.0", note="underlying aggisg api still subject to review and change")]
    pub fn new(secp: &Secp256k1, pubkeys: &Vec<PublicKey>) -> MultiSigContext {
        let mut seed = [0; 32];
        thread_rng().fill_bytes(&mut seed);
        let pubkeys:Vec<*const ffi::PublicKey> = pubkeys.into_iter()
            .map(|p| p.as_ptr())
            .collect();
        let pubkeys = &pubkeys[..];
        unsafe {
            MultiSigContext {
                ctx: secp.ctx,
                aggsig_ctx : ffi::secp256k1_aggsig_context_create(secp.ctx,
                                                                  pubkeys[0],
                                                                  pubkeys.len(),
                                                                  seed.as_ptr()),
            }
        }
    }

    /// Generate a nonce pair for a single signature part in an aggregated signature
    /// Returns: true on success
    ///          false if a nonce has already been generated for this index
    /// In: index: which signature to generate a nonce for
    #[deprecated(since="0.1.0", note="underlying aggsig api still subject to review and change")]
    pub fn generate_nonce(&self, index: usize) -> bool {
        let retval = unsafe {
            ffi::secp256k1_aggsig_generate_nonce(self.ctx, self.aggsig_ctx, index)
        };
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
    #[deprecated(since="0.1.0", note="underlying aggisg api still subject to review and change")]
    pub fn partial_sign(&self, msg:Message, seckey:SecretKey, index: usize) ->
                        Result<AggSigPartialSignature, Error> {
        let mut retsig = AggSigPartialSignature::from(ffi::AggSigPartialSignature::new());
        let retval = unsafe {
            ffi::secp256k1_aggsig_partial_sign(self.ctx,
                                               self.aggsig_ctx,
                                               retsig.as_mut_ptr(),
                                               msg.as_ptr(),
                                               seckey.as_ptr(),
                                               index)
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
    #[deprecated(since="0.1.0", note="underlying aggsig api still subject to review and change")]
    pub fn combine_signatures(&self, partial_sigs: &Vec<AggSigPartialSignature>) ->
                        Result<Signature, Error> {
        let mut retsig = Signature::from(ffi::Signature::new());
        let partial_sigs:Vec<*const ffi::AggSigPartialSignature> = partial_sigs.into_iter()
            .map(|p| p.as_ptr())
            .collect();
        let partial_sigs = &partial_sigs[..];
        let retval = unsafe {
            ffi::secp256k1_aggsig_combine_signatures(self.ctx,
                                               self.aggsig_ctx,
                                               retsig.as_mut_ptr(),
                                               partial_sigs[0],
                                               partial_sigs.len())
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
    #[deprecated(since="0.1.0", note="underlying aggsig api still subject to review and change")]
    pub fn verify(&self, sig: Signature, msg:Message, pks:&Vec<PublicKey>) -> bool {
        let pks:Vec<*const ffi::PublicKey> = pks.into_iter()
            .map(|p| p.as_ptr())
            .collect();
        let pks = &pks[..];
        let retval = unsafe {
            ffi::secp256k1_aggsig_build_scratch_and_verify(self.ctx,
                                                           sig.as_ptr(),
                                                           msg.as_ptr(),
                                                           pks[0],
                                                           pks.len())
        };
        match retval {
          0 => false,
          1 => true,
          _ => false,
        }
    }

}

impl Drop for MultiSigContext {
    fn drop(&mut self) {
        unsafe { ffi::secp256k1_aggsig_context_destroy(self.aggsig_ctx); }
    }
}

#[cfg(test)]
mod tests {
    use ContextFlag;
    use {Message, AggSigPartialSignature};
    use ffi;
    use super::{MultiSigContext, Secp256k1, sign_single, verify_single};
    use rand::{Rng, thread_rng};
    use key::{SecretKey, PublicKey};

    #[test]
    fn test_aggsig_multisig() {
        let numkeys = 5;
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let mut keypairs:Vec<(SecretKey, PublicKey)> = vec![];
        for _ in 0..numkeys {
            keypairs.push(secp.generate_keypair(&mut thread_rng()).unwrap());
        }
        let pks:Vec<PublicKey> = keypairs.clone().into_iter()
            .map(|(_,p)| p)
            .collect();
        println!("Creating aggsig context with {} pubkeys: {:?}", pks.len(), pks);
        let aggsig = MultiSigContext::new(&secp, &pks);
        println!("Generating nonces for each index");
        for i in 0..numkeys {
           let retval=aggsig.generate_nonce(i);
           println!("{} returned {}", i, retval);
           assert!(retval == true);
        }

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let mut partial_sigs:Vec<AggSigPartialSignature> = vec![];
        for i in 0..numkeys {
            println!("Partial sign message: {:?} at index {}, SK:{:?}", msg, i, keypairs[i].0);

            let result = aggsig.partial_sign(msg,keypairs[i].0,i);
            match result {
                Ok(ps) => {
                    println!("Partial sig: {:?}", ps);
                    partial_sigs.push(ps);
                },
                Err(e) => panic!("Partial sig failed: {}", e),
            }
        }

        let result = aggsig.combine_signatures(&partial_sigs);

        let combined_sig = match result {
            Ok(cs) => {
                println!("Combined sig: {:?}", cs);
                cs
            },
            Err(e) => panic!("Combining partial sig failed: {}", e),
        };

        println!("Verifying Combined sig: {:?}, msg: {:?}, pks:{:?}", combined_sig, msg, pks);
        let result = aggsig.verify(combined_sig, msg, &pks);
        println!("Signature verification: {}", result);
    }

    #[test]
    fn test_aggsig_single() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!("Performing aggsig single context with seckey, pubkey: {:?},{:?}", sk, pk);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let sig=sign_single(&secp, msg, sk).unwrap();

        println!("Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}", sig, msg, pk);
        let result = verify_single(&secp, sig, msg, pk);
        println!("Signature verification single (correct): {}", result);
        assert!(result==true);

        let mut msg = [0u8; 32];
        thread_rng().fill_bytes(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        println!("Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}", sig, msg, pk);
        let result = verify_single(&secp, sig, msg, pk);
        println!("Signature verification single (wrong message): {}", result);
        assert!(result==false);
    }
}


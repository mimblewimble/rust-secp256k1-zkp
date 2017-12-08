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

use Error;
use ffi;
use rand::{Rng, thread_rng};
use Message;
use AggSigPartialSignature;
use key::SecretKey;

/// Manages an instance of an aggsig context, and provides all methods
/// to act on that context
#[derive(Clone, Debug)]
pub struct AggSig {
    ctx: *mut ffi::Context,
    aggsig_ctx: *mut ffi::AggSigContext,
}

impl AggSig {
    /// Creates new aggsig context with a new random seed
    pub fn new(secp: &Secp256k1, pubkeys: &[ffi::PublicKey]) -> AggSig {
        let mut seed = [0; 32];
        thread_rng().fill_bytes(&mut seed);
        unsafe {
            AggSig{
                ctx: secp.ctx,
                aggsig_ctx : ffi::secp256k1_aggsig_context_create(secp.ctx,
                                                                  pubkeys.as_ptr(),
                                                                  pubkeys.len(),
                                                                  seed.as_ptr()),
            }
        }
    }

    /// Generate a nonce pair for a single signature part in an aggregated signature
    /// Returns: true on success
    ///          false if a nonce has already been generated for this index
    /// In: index: which signature to generate a nonce for
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
    /// index: which signature to generate a nonce for
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
}

impl Drop for AggSig {
    fn drop(&mut self) {
        unsafe { ffi::secp256k1_aggsig_context_destroy(self.aggsig_ctx); }
    }
}

#[cfg(test)]
mod tests {
    use ContextFlag;
    use ffi;
    use super::{AggSig, Secp256k1};

    #[test]
    fn test_aggsig_context_create() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let mut pks = vec![];
        for _ in 0..10 { 
           pks.push(ffi::PublicKey::new());
        }
        println!("Creating aggsig context with {} pubkeys: {:?}", pks.len(), pks);
        let aggsig = AggSig::new(&secp, &pks);
        println!("Dropping");
    }

    #[test]
    fn test_aggsig_nonce_generate() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let mut pks = vec![];
        let numkeys = 5;
        for _ in 0..numkeys { 
           pks.push(ffi::PublicKey::new());
        }
        println!("Creating aggsig context with {} pubkeys: {:?}", pks.len(), pks);
        let aggsig = AggSig::new(&secp, &pks);
        println!("Generating nonces for each index");
        for i in 0..numkeys {
           let retval=aggsig.generate_nonce(i);
           println!("{} returned {}", i, retval);
           assert!(retval == true);
        }
        println!("Dropping");
    }

    #[test]
    fn test_aggsig_partial_sign() {
       // TODO next task
    }
}


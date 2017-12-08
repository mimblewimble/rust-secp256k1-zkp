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


use ContextFlag;
use Error;
use Secp256k1;

use constants;
use ffi;
use key;
use super::{Message, Signature};
use rand::{Rng, thread_rng};
use serde::{ser, de};

/// Manages an instance of an aggsig context, and provides all methods
/// to act on that context
#[derive(Clone, Debug)]
pub struct AggSig {
    aggsig_ctx: *mut ffi::AggSigContext,
}

impl AggSig {
    /// Creates new aggsig context with a new random seed
    pub fn new(secp: &Secp256k1, pubkeys: &[ffi::PublicKey]) -> AggSig {
        let mut seed = [0; 32];
        thread_rng().fill_bytes(&mut seed);
        unsafe {
            AggSig{
                aggsig_ctx : ffi::secp256k1_aggsig_context_create(secp.ctx, 
                                                                  pubkeys.as_ptr(),
                                                                  pubkeys.len(),
                                                                  seed.as_ptr()),
            }
        }
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
        for _ in 0..1000 { 
           pks.push(ffi::PublicKey::new());
        }
        println!("Creating aggsig context with {} pubkeys: {:?}", pks.len(), pks);
        let aggsig = AggSig::new(&secp, &pks);
        println!("Dropping");
    }
}


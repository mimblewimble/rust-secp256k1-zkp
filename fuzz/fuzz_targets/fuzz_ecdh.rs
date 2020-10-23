#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate secp256k1zkp;

use secp256k1zkp::{Secp256k1, PublicKey, SecretKey};
use secp256k1zkp::ecdh::SharedSecret;

fuzz_target!(|keys: (SecretKey, PublicKey)| {
    let s = Secp256k1::new();
    let (sk, pk) = keys;

    let _ = SharedSecret::new(&s, &pk, &sk);
});

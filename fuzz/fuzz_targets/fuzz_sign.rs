#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate secp256k1zkp;

use secp256k1zkp::{Message, Secp256k1, PublicKey, SecretKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return ();
    }

    let s = Secp256k1::new();

    let msg = Message::from_slice(&data[..32]).unwrap();

    if let Ok(sk) = SecretKey::from_slice(&s, &data[32..64]) {
        match s.sign(&msg, &sk) {
            Ok(sig) => {
                match PublicKey::from_secret_key(&s, &sk) {
                    Ok(pk) => s.verify(&msg, &sig, &pk).unwrap(),
                    Err(e) => panic!("cannot create public key from secret: {}", e),
                }
            }
            Err(e) => panic!("error creating signature: {}", e),
        }
    }
});

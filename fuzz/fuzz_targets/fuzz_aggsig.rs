#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate secp256k1zkp;

use secp256k1zkp::{
    AggSigPartialSignature,
    ContextFlag,
    Message,
    Secp256k1,
    PublicKey,
    SecretKey
};

use secp256k1zkp::aggsig::AggSigContext;

fuzz_target!(|keys_msg: (Vec<(SecretKey, PublicKey)>, Message)| {
    let (keys, msg) = keys_msg;
    let numkeys = keys.len();

    if numkeys == 0 { return }

    let secp = Secp256k1::with_caps(ContextFlag::Full);

    // public keys for valid verification
    let mut pks: Vec<PublicKey> = Vec::with_capacity(numkeys);

    for (sk, _) in keys.iter() {
        let pk = PublicKey::from_secret_key(&secp, &sk).unwrap();
        pks.push(pk.clone());
    }

    let aggsig = AggSigContext::new(&secp, &pks);

    // generate signature nonces
    for i in 0..numkeys {
        if aggsig.generate_nonce(i) != true {
            panic!("failed to generate aggsig nonce: {}", i);
        }
    }
 
    let mut partial_sigs: Vec<AggSigPartialSignature> = vec![];

    // create partial signatures
    for (i, (sk, _)) in keys.iter().enumerate() {
        match aggsig.partial_sign(msg.clone(), sk.clone(), i) {
            Ok(res) => partial_sigs.push(res),
            Err(e) => panic!("error creating partial signature: {:?}", e),
        }
    }

    // aggregate signatures
    match aggsig.combine_signatures(&partial_sigs) {
        Ok(full_sig) => {
            // verify with valid keys
            assert!(aggsig.verify(full_sig, msg.clone(), &pks));
            // verify with random keys, unlikely to ever return true
            assert_eq!(aggsig.verify(full_sig, msg.clone(), &keys.iter().map(|(_, pk)| *pk).collect::<Vec<PublicKey>>()), false);
        },
        Err(e) => panic!("error combining signatures: {:?}", e),
    }
});

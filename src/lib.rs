extern crate crypto;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn sign(message: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let sig = crypto::ed25519::signature(message, secret_key);
    sig.to_vec()
}

#[wasm_bindgen]
pub fn verify(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    crypto::ed25519::verify(message, public_key, signature)
}

#[wasm_bindgen]
pub fn keypair(seed: &[u8]) -> Vec<u8> {
    let (r1, r2) = crypto::ed25519::keypair(seed);
    let mut res = r1.to_vec();
    res.extend_from_slice(&r2);
    res
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let msg = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
        let sk = vec![103,198,105,115,81,255,74,236,41,205,186,
                      171,242,251,227,70,124,194,84,248,27,232,
                      231,141,118,90,46,99,51,159,201,154,175,
                      205,83,68,59,121,13,42,239,69,157,200,190,
                      188,61,166,34,79,251,146,170,128,25,76,95,
                      14,99,40,227,228,73,39];
        let pk = vec![175,205, 83, 68, 59,121, 13, 42,
                      239, 69,157,200,190,188, 61,166,
                      34 , 79,251,146,170,128, 25, 76,
                      95 , 14, 99, 40,227,228, 73, 39];

        for i in 0 .. 10000 {
            let sig = super::sign(&msg, &sk);
            if i == 9000 {
                println!("{} -> sig = {:?}", i, sig);
            }

            assert!(super::verify(&msg, &pk, &sig))
        }
    }
}

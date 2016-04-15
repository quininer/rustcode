extern crate num;
extern crate rustc_serialize;
extern crate implement_rsa;
extern crate implement_diffie_hellman;
extern crate cbc_bitflipping_attacks;

use num::BigUint;
use implement_rsa::RSA;
use implement_diffie_hellman::{ modexp, TWO, ONE, ZERO };


/// 1 -> true, 2 -> false
pub type ParityVerify = Box<Fn(&[u8]) -> bool>;

pub fn crack_rsa_with_parity_decryptor(rsa: &RSA, ciphertext: &[u8], verify: ParityVerify) -> Vec<u8> {
    let mut ciphernum = BigUint::from_bytes_be(ciphertext);
    let k = modexp(&TWO, &rsa.e, &rsa.n);
    let (mut low, mut high, mut count) = (ZERO.clone(), ONE.clone(), ONE.clone());
    for _ in 0..rsa.n.bits() {
        ciphernum = (&ciphernum * &k) % &rsa.n;
        let d = &high - &low;
        low = &low * TWO.clone();
        high = &high * TWO.clone();
        count = &count * TWO.clone();
        if verify(&ciphernum.to_bytes_be()) {
            low = &low + &d;
        } else {
            high = &high - &d;
        };
    }
    (&rsa.n * &high / &count).to_bytes_be()
}


#[test]
fn it_works() {
    use num::Integer;
    use rustc_serialize::base64::FromBase64;
    use cbc_bitflipping_attacks::Cipher;

    let plaintext = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
        .from_base64()
        .unwrap();

    let rsa = RSA::with_size(1024);
    let ciphertext = rsa.encrypt(&plaintext);

    assert_eq!(
        crack_rsa_with_parity_decryptor(
            &rsa.public(),
            &ciphertext,
            Box::new(move |u| !BigUint::from_bytes_be(&rsa.decrypt(u)).is_even())
        ),
        plaintext
    );
}

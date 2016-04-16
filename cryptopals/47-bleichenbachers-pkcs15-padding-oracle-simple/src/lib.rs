#![feature(question_mark)]

extern crate num;
extern crate implement_rsa;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate implement_diffie_hellman;
#[macro_use] extern crate an_ebccbc_detection_oracle;

mod pkcs115;

use num::BigUint;
use implement_rsa::RSA;
use implement_diffie_hellman::{ modexp, ONE, THREE };
pub use pkcs115::{ padding, unpadding };

/// plaintext is pkcs1 1.5 formatted
pub type Verifyer = Box<Fn(&[u8]) -> bool>;
///  RSA, B, CipherNum
pub type RsaArgs = (RSA, BigUint, BigUint);
/// Plaintext Interval: lower, upper
pub type Interval = (BigUint, BigUint);


pub fn crack_rsa_padding_simple(verify: Verifyer) -> Vec<u8> {
    unimplemented!()
}


#[test]
fn it_works() {
    use cbc_bitflipping_attacks::Cipher;

    let message = b"kick it, CC";

    let rsa = RSA::with_size(256);
    let len = (rsa.n.bits() + 7) / 8;
    let ciphertext = rsa.encrypt(&padding(message, len));

    assert_eq!(
        unpadding(&rsa.decrypt(&ciphertext), len).unwrap(),
        message
    );

    assert_eq!(
        unpadding(&crack_rsa_padding_simple(
            Box::new(move |u| unpadding(&rsa.decrypt(u), len).is_ok())
        ), len).unwrap(),
        message
    );
}

#![feature(question_mark)]

extern crate num;
extern crate implement_rsa;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate implement_diffie_hellman;
#[macro_use] extern crate an_ebccbc_detection_oracle;

mod pkcs115;

use std::cmp::{ max, min };
use num::{ BigUint, pow, range };
use implement_rsa::RSA;
use implement_diffie_hellman::{ modexp, ONE, TWO, THREE };
pub use pkcs115::{ padding, unpadding };


/// plaintext is pkcs1 1.5 formatted
pub type Verifyer = Box<Fn(&[u8]) -> bool>;
/// RSA, B, CipherNum
pub type RsaArgs = (RSA, BigUint, BigUint);
/// Plaintext M: lower, upper
pub type M = (BigUint, BigUint);

pub fn first_s(&(ref rsa, ref bb, ref c0): &RsaArgs, verify: &Verifyer) -> BigUint {
    let mut s = (&rsa.n + bb * THREE.clone() - ONE.clone()) / (bb * THREE.clone());
    while !verify(&(c0 * modexp(&s, &rsa.e, &rsa.n) % &rsa.n).to_bytes_be()) {
        s = s + ONE.clone();
    }
    s.clone()
}

pub fn next_s(
    &(ref rsa, ref bb, ref c0): &RsaArgs,
    verify: &Verifyer,
    &(ref a, ref b): &M,
    s: &BigUint
) -> BigUint {
    let mut r = (TWO.clone() * (b * s - bb * TWO.clone()) + &rsa.n - ONE.clone()) / &rsa.n;
    loop {
        for s in range(
            (bb * TWO.clone() + &r * &rsa.n + b - ONE.clone()) / b,
            (bb * THREE.clone() + &r * &rsa.n + a - ONE.clone()) / a
        ) {
            if verify(&(c0 * modexp(&s, &rsa.e, &rsa.n) % &rsa.n).to_bytes_be()) {
                return s
            }
        };
        r = r + ONE.clone();
    }
}

pub fn next_interval(
    &(ref rsa, ref bb, _): &RsaArgs,
    &(ref a, ref b): &M,
    s: &BigUint
) -> M {
    let r = (a * s - bb * THREE.clone() + &rsa.n) / &rsa.n;
    (
        max(a.clone(), (bb * TWO.clone() + &r * &rsa.n + s - ONE.clone()) / s),
        min(b.clone(), (bb * THREE.clone() + &r * &rsa.n - ONE.clone()) / s)
    )
}

pub fn crack_rsa_padding_simple(rsa: &RSA, ciphertext: &[u8], verify: Verifyer) -> Vec<u8> {
    let k = (rsa.n.bits() + 7) / 8;
    let rsa_args = (
        rsa.clone(),
        pow(TWO.clone(), 8 * (k - 2)),
        BigUint::from_bytes_be(ciphertext)
    );
    let mut messages = (
        &rsa_args.1 * TWO.clone(),
        &rsa_args.1 * THREE.clone() - ONE.clone()
    );
    let mut s = first_s(&rsa_args, &verify);
    messages = next_interval(&rsa_args, &messages, &s);

    while &messages.0 != &messages.1 {
        s = next_s(&rsa_args, &verify, &messages, &s);
        messages = next_interval(&rsa_args, &messages, &s);
    }

    messages.0.to_bytes_be()
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
            &rsa.clone(),
            &ciphertext,
            Box::new(move |u| unpadding(&rsa.decrypt(u), len).is_ok())
        ), len).unwrap(),
        message
    );
}

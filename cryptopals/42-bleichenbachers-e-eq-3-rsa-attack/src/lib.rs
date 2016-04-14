extern crate num;
extern crate regex;
extern crate implement_an_e_eq_3_rsa_broadcast_attack;
extern crate implement_rsa;
extern crate implement_diffie_hellman;
extern crate implement_a_sha_1_keyed_mac;
extern crate cbc_bitflipping_attacks;

use num::BigUint;
use regex::bytes::Regex;
use implement_an_e_eq_3_rsa_broadcast_attack::floor_root;
use implement_rsa::RSA;
use implement_diffie_hellman::ONE;
use implement_a_sha_1_keyed_mac::{ Sha1, Digest };
use cbc_bitflipping_attacks::Cipher;


pub fn padding(digest: &[u8]) -> Vec<u8> {
    [
        vec![0x00, 0x01],
        vec![0xff; 128 - digest.len() - 3],
        vec![0x00],
        digest.into()
    ].concat()
}

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;
}

impl Signer for RSA {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.decrypt(&padding(&Sha1::hash(data)))
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let block = self.encrypt(signature);

        // XXX because bytes to bituint missing leading zero.
        // r"\x00\x01\xff+?\x00(.{20})"
        Regex::new(r"\x01\xff+?\x00([\x00-\xff]{20})").unwrap()
            .captures(&block)
            .and_then(|matches| matches.at(1))
            .map_or(false, |matches| Sha1::hash(data) == matches)
    }
}

pub fn crack_rsa_sign_bleichenbachers_eeq3(message: &[u8]) -> Vec<u8> {
    let digest = Sha1::hash(message);
    let block = [
        vec![0x00, 0x01, 0xff, 0x00],
        digest.clone(),
        vec![0x00; 128 - digest.len() - 4]
    ].concat();
    (
        floor_root(&BigUint::from_bytes_be(&block), 3)
            + ONE.clone()
    ).to_bytes_be()
}


#[test]
fn it_works() {
    let message = b"hi mom";
    let rsa = RSA::with_size(1024);

    let fake_signature = crack_rsa_sign_bleichenbachers_eeq3(message);
    assert!(rsa.verify(message, &fake_signature));
}

#[test]
fn test_sign() {
    let message = b"hi mom";
    let rsa = RSA::with_size(1024);
    let signature = rsa.sign(message);

    assert!(rsa.verify(message, &signature));
    assert!(!rsa.verify(message, &Sha1::hash(message)));
    assert!(!rsa.verify(&message[1..], &signature));
}

#![feature(slice_patterns)]

extern crate num;
extern crate rustc_serialize;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate implement_diffie_hellman;

mod invmod;

use num::BigUint;
use rustc_serialize::hex::FromHex;
use cbc_bitflipping_attacks::Cipher;
use implement_diffie_hellman::{ modexp, ONE as UONE };
pub use invmod::{ uinvmod, invmod, egcd, ZERO, ONE };


lazy_static!{
    pub static ref PRIMES: Vec<BigUint> = include_str!("primes.txt").lines()
        .map(|u| u.from_hex().unwrap())
        .map(|u| BigUint::from_bytes_be(&u))
        .collect();
}

pub struct RSA {
    sk: Option<BigUint>,
    pub pk: BigUint,
    pub n : BigUint
}

impl Default for RSA {
    fn default() -> RSA {
        let r = rand!(choose PRIMES.clone(), 2);
        let (p, q) = (&r[0], &r[1]);
        let e = BigUint::from(3u32);
        let n = p * q;
        let et = (p - UONE.clone()) * (q - UONE.clone());

        RSA::new(&uinvmod(&e, &et), &e, &n)
    }
}

impl RSA {
    pub fn new(sk: &Option<BigUint>, pk: &BigUint, n: &BigUint) -> RSA {
        RSA { sk: sk.clone(), pk: pk.clone(), n: n.clone() }
    }
}

impl Cipher for RSA {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        modexp(
            &BigUint::from_bytes_be(data),
            &self.pk,
            &self.n
        ).to_bytes_be()
    }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        modexp(
            &BigUint::from_bytes_be(data),
            &self.sk.clone().unwrap(),
            &self.n
        ).to_bytes_be()
    }
}


#[test]
fn it_works() {
    use implement_diffie_hellman::ZERO as UZERO;

    let rsa = RSA::default();

    let plaintext = b"oh my rsa!";
    let ciphertext = rsa.encrypt(plaintext);
    assert_eq!(
        rsa.decrypt(&ciphertext),
        plaintext
    );

    assert_eq!(
        BigUint::from_bytes_be(&rsa.encrypt(&UZERO.to_bytes_be())),
        UZERO.clone()
    );

    let p1 = BigUint::from(rand!(choose 1..10) as u32);
    let p2 = BigUint::from(rand!(choose 1..10) as u32);
    let c1 = BigUint::from_bytes_be(&rsa.encrypt(&p1.to_bytes_be()));
    let c2 = BigUint::from_bytes_be(&rsa.encrypt(&p2.to_bytes_be()));
    assert_eq!(
        BigUint::from_bytes_be(&rsa.decrypt(&(c1 * c2).to_bytes_be())),
        p1 * p2
    );
}

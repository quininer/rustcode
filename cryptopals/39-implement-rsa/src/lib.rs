extern crate num;
extern crate rustc_serialize;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate implement_diffie_hellman;

mod inv;

use num::BigUint;
use num::bigint::{ ToBigInt, ToBigUint };
use rustc_serialize::hex::FromHex;
use cbc_bitflipping_attacks::Cipher;
use implement_diffie_hellman::{ modexp, ONE as UONE };
pub use inv::{ invmod, egcd, ZERO, ONE };


lazy_static!{
    pub static ref PRIMES: Vec<BigUint> = include_str!("primes.txt").lines()
        .map(|u| u.from_hex().unwrap())
        .map(|u| BigUint::from_bytes_be(&u))
        .collect();
}

pub struct RSA {
    sk: Option<BigUint>,
    pk: BigUint,
    n : BigUint
}

impl Default for RSA {
    fn default() -> RSA {
        let p = &rand!(choose PRIMES.clone());
        let q = &rand!(choose PRIMES.clone());
        let n = p * q;
        let et = (p - UONE.clone()) * (q - UONE.clone());
        let e = BigUint::from(3u32);

        // FIXME BigInt or BigUint ?
        let d = invmod(
            &e.to_bigint().unwrap(),
            &et.to_bigint().unwrap()
        ).and_then(|u| u.to_biguint());

        RSA::new(&d, &e, &n)
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
    let plaintext = b"oh my rsa!";
    let rsa = RSA::default();

    let ciphertext = rsa.encrypt(plaintext);

    assert_eq!(
        rsa.decrypt(&ciphertext),
        plaintext
    );
}

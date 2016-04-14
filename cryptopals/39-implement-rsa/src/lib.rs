#![feature(slice_patterns)]

extern crate num;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate implement_diffie_hellman;

mod primes;
mod invmod;

use num::BigUint;
use cbc_bitflipping_attacks::Cipher;
use implement_diffie_hellman::{ modexp, ONE as UONE };
pub use invmod::{ uinvmod, invmod, egcd, ZERO, ONE };
pub use primes::{ SMALL_PRIMES, gen_prime, is_prime };


lazy_static!{
    pub static ref E: BigUint = BigUint::from(3u32);
}

#[derive(Clone)]
pub struct RSA {
    sk: Option<BigUint>,
    pub e: BigUint,
    pub n : BigUint
}

impl Default for RSA {
    fn default() -> RSA {
        RSA::with_size(128)
    }
}

impl RSA {
    pub fn with_size(size: usize) -> RSA {
        let mut p = E.clone() + UONE.clone();
        while &p % E.clone() == UONE.clone() {
            p = gen_prime(size);
        }
        let mut q = E.clone() + UONE.clone();
        while &q % E.clone() == UONE.clone() {
            q = gen_prime(size);
        }

        RSA::from(&p, &q, &E)
    }

    pub fn new(sk: &Option<BigUint>, e: &BigUint, n: &BigUint) -> RSA {
        RSA { sk: sk.clone(), e: e.clone(), n: n.clone() }
    }

    pub fn from(p: &BigUint, q: &BigUint, e: &BigUint) -> RSA {
        let n = p * q;
        let et = (p - UONE.clone()) * (q - UONE.clone());
        RSA::new(&uinvmod(&e, &et), &e, &n)
    }

    pub fn public(&self) -> RSA {
        RSA {
            sk: None,
            e: self.e.clone(),
            n: self.n.clone()
        }
    }
}

impl Cipher for RSA {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        modexp(
            &BigUint::from_bytes_be(data),
            &self.e,
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
    let ciphertext = rsa.public().encrypt(plaintext);
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

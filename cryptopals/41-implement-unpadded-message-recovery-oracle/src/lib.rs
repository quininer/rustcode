extern crate num;
extern crate implement_rsa;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate implement_diffie_hellman;

use std::collections::HashSet;
use num::BigUint;
use cbc_bitflipping_attacks::Cipher;
use implement_diffie_hellman::{ modexp, TWO };
use implement_rsa::{ RSA, uinvmod };


pub type Decryptor = Box<FnMut(&[u8]) -> Vec<u8>>;

#[derive(Clone)]
pub struct RsaOracle {
    set: HashSet<Vec<u8>>,
    rsa: RSA
}

impl Default for RsaOracle {
    fn default() -> RsaOracle {
        RsaOracle::new()
    }
}

impl RsaOracle {
    pub fn new() -> RsaOracle {
        RsaOracle {
            set: HashSet::new(),
            rsa: RSA::with_size(256)
        }
    }
    pub fn public(&self) -> RSA {
        self.rsa.public()
    }
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.rsa.encrypt(&data)
    }
    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if self.set.insert(data.into()) {
            Some(self.rsa.decrypt(data))
        } else {
            None
        }
    }
}

pub fn crack_rsa_with_decryptor(rsa: &RSA, ciphertext: &[u8], mut decryptor: Decryptor) -> Vec<u8> {
    let s = rand_big!(&TWO, &rsa.n);
    let cc = (
        modexp(&s, &rsa.e, &rsa.n)
            * BigUint::from_bytes_be(ciphertext)
    ) % &rsa.n;
    let cp = BigUint::from_bytes_be(&decryptor(&cc.to_bytes_be()));
    let plaintext = (cp * &uinvmod(&s, &rsa.n).unwrap()) % &rsa.n;
    plaintext.to_bytes_be()
}


#[test]
fn it_works() {
    let text = rand!(16);
    let mut oracle = RsaOracle::new();
    let ciphertext = oracle.encrypt(&text);
    assert_eq!(oracle.decrypt(&ciphertext), Some(text.clone()));
    assert!(oracle.decrypt(&ciphertext).is_none());
    assert_eq!(
        crack_rsa_with_decryptor(
            &oracle.public(),
            &ciphertext,
            Box::new(move |u| oracle.decrypt(u).unwrap())
        ),
        text
    );
}

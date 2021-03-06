extern crate num;
extern crate implement_rsa;
extern crate cbc_bitflipping_attacks;
extern crate implement_diffie_hellman;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use num::BigUint;
use implement_diffie_hellman::{ TWO, ONE, ZERO };
use implement_rsa::{ RSA, uinvmod };


pub fn floor_root(n: &BigUint, e: usize) -> BigUint {
    let mut high = ONE.clone();
    while &num::pow(high.clone(), e) < n {
        high = &high * TWO.clone();
    }
    let mut low = &high / TWO.clone();

    while &low < &high {
        let mid = (&low + &high) / TWO.clone();
        let p = num::pow(mid.clone(), e);
        if low < mid && p < n.clone() {
            low = mid;
        } else if high > mid && p > n.clone() {
            high = mid;
        } else {
            return mid;
        }
    }

    &low + ONE.clone()
}

pub fn crack_rsa_with_crt(ciphers: &[(RSA, Vec<u8>)], exps: usize) -> Vec<u8> {
    let n012 = ciphers.iter()
        .map(|r| r.0.n.clone())
        .fold(ONE.clone(), |sum, next| sum * next);
    let result = ciphers.iter()
        .zip(
            ciphers.iter()
                .map(|r| r.0.n.clone())
                .map(|r| &n012 / r)
        )
        .map(|(&(ref rsa, ref text), ref ms)|
            BigUint::from_bytes_be(text)
                * ms
                * uinvmod(ms, &rsa.n).unwrap()
        )
        .fold(ZERO.clone(), |sum, next| sum + next) % n012;

    floor_root(&result, exps).to_bytes_be()
}


#[test]
fn it_works() {
    use num::ToPrimitive;
    use cbc_bitflipping_attacks::Cipher;
    use implement_rsa::E;

    let plaintext = rand!(16);
    let e = E.to_u64().map(|n| n as usize);

    assert_eq!(e, Some(3));

    let ciphers: Vec<(RSA, Vec<u8>)> = (0..e.unwrap())
        .map(|_| {
            let rsa = RSA::with_size(256);
            (rsa.public(), rsa.encrypt(&plaintext))
        })
        .collect();

    assert_eq!(
        crack_rsa_with_crt(&ciphers, e.unwrap()),
        plaintext
    );
}

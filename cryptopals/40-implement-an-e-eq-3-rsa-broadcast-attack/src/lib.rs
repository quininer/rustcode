extern crate num;
extern crate implement_rsa;
extern crate cbc_bitflipping_attacks;
extern crate implement_diffie_hellman;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use num::BigUint;
use implement_diffie_hellman::{ ONE, ZERO };
use implement_rsa::{ RSA, uinvmod };


pub fn cube_root(n: &BigUint, e: usize) -> BigUint {
    let two = BigUint::from(2u32);
    let mut high = ONE.clone();
    while &num::pow(high.clone(), e) < n {
        high = &high * &two;
    }
    let mut low = &high / &two;

    while &low < &high {
        let mid = (&low + &high) / &two;
        let pow = num::pow(mid.clone(), e);
        if low < mid && pow < n.clone() {
            low = mid;
        } else if high > mid && pow > n.clone() {
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

    cube_root(&result, exps).to_bytes_be()
}


#[test]
fn it_works() {
    use num::ToPrimitive;
    use cbc_bitflipping_attacks::Cipher;
    use implement_rsa::{ PRIMES, E };

    let plaintext = rand!(16);

    let ciphers: Vec<(RSA, Vec<u8>)> = rand!(choose PRIMES.clone(), 6)
        .chunks(2)
        .map(|pq| {
            let rsa = RSA::from(&pq[0], &pq[1], &E);
            (rsa.public(), rsa.encrypt(&plaintext))
        }).collect();

    assert_eq!(E.to_u64(), Some(3));
    assert_eq!(
        crack_rsa_with_crt(&ciphers, E.to_u64().unwrap() as usize),
        plaintext
    );
}

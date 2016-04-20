extern crate num;
extern crate bleichenbachers_pkcs15_padding_oracle_simple;
extern crate implement_rsa;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate implement_diffie_hellman;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use std::cmp::{ max, min };
use num::{ BigUint, pow, range };
use implement_rsa::RSA;
use implement_diffie_hellman::{ ONE, TWO, THREE };
use bleichenbachers_pkcs15_padding_oracle_simple::{
    RsaArgs, Verifyer, M,
    first_s, next_s
};


pub fn next_intervals(
    &(ref rsa, ref bb, _): &RsaArgs,
    s: &BigUint,
    intervals: &[M]
) -> Vec<M> {
    let mut out = Vec::new();
    for &(ref a, ref b) in intervals {
        for r in range(
            (a * s - bb * THREE.clone() + &rsa.n) / &rsa.n,
            ((b * s - bb * TWO.clone()) / &rsa.n) + ONE.clone()
        ) {
            let lower = max(a.clone(), (bb * TWO.clone() + &r * &rsa.n + s - ONE.clone()) / s);
            let upper = min(b.clone(), (bb * THREE.clone() + &r * &rsa.n - ONE.clone()) / s);
            if lower > upper { continue };
            out.push((lower, upper));
        }
    }
    out
}

pub fn crack_rsa_padding_complete(rsa: &RSA, ciphertext: &[u8], verify: Verifyer) -> Vec<u8> {
    let k = (rsa.n.bits() + 7) / 8;
    let rsa_args = (
        rsa.clone(),
        pow(TWO.clone(), 8 * (k - 2)),
        BigUint::from_bytes_be(ciphertext)
    );
    let m = (
        &rsa_args.1 * TWO.clone(),
        &rsa_args.1 * THREE.clone() - ONE.clone()
    );
    let mut s = first_s(&rsa_args, &verify, None);
    let mut intervals = Vec::new();
    intervals.push(m);

    loop {
        intervals = next_intervals(&rsa_args, &s, &intervals);
        if intervals.len() == 1 {
            let m = intervals[0].clone();
            if m.0 == m.1 { return m.0.to_bytes_be() };
            s = next_s(&rsa_args, &verify, &s, &m);
        } else {
            s = first_s(&rsa_args, &verify, Some(s));
        };
    }
}


#[test]
fn it_works() {
    use bleichenbachers_pkcs15_padding_oracle_simple::{ padding, unpadding };
    use cbc_bitflipping_attacks::Cipher;

    let message = b"kick it, CC";

    let rsa = RSA::with_size(768);
    let len = (rsa.n.bits() + 7) / 8;
    let ciphertext = rsa.encrypt(&padding(message, len));

    assert_eq!(
        unpadding(&rsa.decrypt(&ciphertext), len).unwrap(),
        message
    );

    assert_eq!(
        unpadding(&crack_rsa_padding_complete(
            &rsa.clone(),
            &ciphertext,
            Box::new(move |u| rsa.decrypt(u).starts_with(b"\x02"))
            // Box::new(move |u| unpadding(&rsa.decrypt(u), len).is_ok())
        ), len).unwrap(),
        message
    );
}

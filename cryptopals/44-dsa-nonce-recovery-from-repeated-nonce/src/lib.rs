extern crate num;
extern crate rustc_serialize;
extern crate dsa_key_recovery_from_nonce;
extern crate implement_rsa;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate implement_diffie_hellman;

use num::{ BigUint, BigInt };
use num::bigint::ToBigInt;
use implement_rsa::invmod;


pub type DsaLog = (String, BigInt, BigInt, BigInt);

pub fn recover_dsa_k_from_log(q: &BigUint, log1: &DsaLog, log2: &DsaLog) -> Option<BigUint> {
    let q = q.to_bigint().unwrap();
    let top = (&log1.3 - &log2.3) % &q;
    let bottom = (&log1.1 - &log2.1) % &q;
    (top * invmod(&bottom, &q)).to_biguint()
}


#[test]
fn it_works() {
    use std::fs::File;
    use std::io::Read;
    use rustc_serialize::hex::ToHex;
    use dsa_key_recovery_from_nonce::{ DSA, recover_dsa_from_k, P, Q, G };
    use implement_a_sha_1_keyed_mac::{ Sha1, Digest };

    let mut input = String::new();
    File::open("examples/44.txt").unwrap()
        .read_to_string(&mut input).unwrap();
    let input: Vec<DsaLog> = input.lines()
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
        .chunks(4)
        .map(|r| (
            String::from(&r[0][5..]),
            r[1][3..].parse().unwrap(),
            r[2][3..].parse().unwrap(),
            BigInt::from_bytes_be(
                num::bigint::Sign::Plus,
                &Sha1::hash(&r[0][5..].as_bytes())
            )
            // hex_to_bigint!(&r[3][3..])
        ))
        .collect();

    // XXX order
    let log1 = &input[0];
    let log2 = input.iter()
        .find(|log| log.0 != log1.0 && log.2 == log1.2)
        .unwrap();

    let y = hex_to_bigint!(u"
2d026f4bf30195ede3a088da85e398ef869611d0f68f07
13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
2971c3de5084cce04a2e147821");

    let dsa = DSA {
        x: None,
        p: P.clone(),
        q: Q.clone(),
        g: G.clone(),
        y: y.clone()
    };

    let k = recover_dsa_k_from_log(&dsa.q, &log2, &log1).unwrap();
    let rdsa = recover_dsa_from_k(
        &dsa,
        &log1.2.to_biguint().unwrap(),
        &log1.1.to_biguint().unwrap(),
        &k,
        &log1.3.to_biguint().unwrap()
    ).unwrap();

    assert_eq!(
        Sha1::hash(&rdsa.x.unwrap().to_bytes_be().to_hex().into_bytes()).to_hex(),
        "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    );
}

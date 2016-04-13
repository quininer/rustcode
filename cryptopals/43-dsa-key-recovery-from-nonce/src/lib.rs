extern crate num;
extern crate rustc_serialize;
extern crate implement_rsa;
extern crate implement_a_sha_1_keyed_mac;
extern crate bleichenbachers_e_eq_3_rsa_attack;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate implement_diffie_hellman;

mod dsa;

use num::BigUint;
use implement_rsa::uinvmod;
use implement_diffie_hellman::modexp;
pub use dsa::DSA;


lazy_static!{
    pub static ref P: BigUint = hex_to_bigint!(u"
800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1");
    pub static ref Q: BigUint = hex_to_bigint!(u"f4f47f05794b256174bba6e9b396a7707e563c5b");
    pub static ref G: BigUint = hex_to_bigint!(u"
5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291");
}

pub fn recover_dsa_from_k(
    pk: &DSA,
    r: &BigUint,
    s: &BigUint,
    k: &BigUint,
    msghash: &BigUint
) -> Result<DSA, ()> {
    if &(s * k) < msghash { return Err(()) };
    let x = ((s * k) - msghash) * uinvmod(r, &pk.q).unwrap() % &pk.q;
    if modexp(&pk.g, &x, &pk.p) == pk.y {
        let mut pk = pk.clone();
        pk.x = Some(x);
        Ok(pk)
    } else {
        Err(())
    }
}


#[test]
fn it_works() {
    use rustc_serialize::hex::ToHex;
    use implement_a_sha_1_keyed_mac::{ Sha1, Digest };

    let r: BigUint = "548099063082341131477253921760299949438196259240".parse().unwrap();
    let s: BigUint = "857042759984254168557880549501802188789837994940".parse().unwrap();
    let msghash = hex_to_bigint!(u"d2d0714f014a9784047eaeccf956520045c45265");

    // missing leading zero..
    let y = hex_to_bigint!(u"
084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
bb283e6633451e535c45513b2d33c99ea17");

    let dsa = DSA {
        x: None,
        p: P.clone(),
        q: Q.clone(),
        g: G.clone(),
        y: y.clone()
    };

    // XXX 0..2^16
    let k = (16574..(2u32.pow(16)+1)).find(|&k| recover_dsa_from_k(
        &dsa,
        &r,
        &s,
        &BigUint::from(k),
        &msghash
    ).is_ok()).unwrap();
    let rdsa = recover_dsa_from_k(
        &dsa,
        &r,
        &s,
        &BigUint::from(k),
        &msghash
    ).unwrap();

    assert_eq!(
        Sha1::hash(&rdsa.x.unwrap().to_bytes_be().to_hex().into_bytes()).to_hex(),
        "0954edd5e0afe5542a4adf012611a91912a3ec16"
    );
}

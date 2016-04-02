extern crate rustc_serialize;
extern crate rand;
extern crate num;
#[macro_use] extern crate lazy_static;

use rustc_serialize::hex::FromHex;
use rand::thread_rng;
use num::bigint::{ BigUint, RandBigInt };
use num::traits::{ Zero, One };
use num::pow;

lazy_static! {
    pub static ref P: BigUint = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff"
        .from_hex().ok()
        .map(|n| BigUint::from_bytes_be(&n))
        .unwrap();
    pub static ref G: BigUint = BigUint::from(2u32);
}


pub struct DH {
    p: BigUint,
    s: BigUint,
    pub k: BigUint
}

impl Default for DH {
    fn default() -> DH {
        DH::new(P.clone(), G.clone())
    }
}

impl DH {
    pub fn new(p: BigUint, g: BigUint) -> DH {
        let s = thread_rng().gen_biguint_range(&BigUint::zero(), &p);
        DH {
            p: p.clone(),
            s: s.clone(),
            k: modexp(
                g.clone(),
                s.clone(),
                p.clone()
            )
        }
    }
}

pub trait NumExchange {
    fn num_exchange(&self, token: &BigUint) -> BigUint;
}

impl NumExchange for DH {
    fn num_exchange(&self, token: &BigUint) -> BigUint {
        modexp(token.clone(), self.s.clone(), self.p.clone())
    }
}

pub fn modexp(mut base: BigUint, mut exps: BigUint, mods: BigUint) -> BigUint {
    let mut out = BigUint::one();

    while exps > BigUint::zero() {
        if exps.clone() & BigUint::one() == BigUint::one() {
            out = out * base.clone() % mods.clone();
        }

        base = pow(base.clone(), 2);
        base = base % mods.clone();
        exps = exps >> 1;
    }

    out
}


#[test]
fn test_dh() {
    let alice = DH::default();
    let bob = DH::default();

    assert_eq!(
        alice.num_exchange(&bob.k),
        bob.num_exchange(&alice.k)
    );
}

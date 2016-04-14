extern crate rustc_serialize;
extern crate rand;
extern crate num;
#[macro_use] extern crate lazy_static;

pub use rustc_serialize::hex::FromHex;
pub use num::{ BigUint, BigInt };
pub use num::bigint::Sign;
use num::traits::{ Zero, One };
use num::pow;
pub use rand::thread_rng;


#[macro_export]
macro_rules! hex_to_bigint {
    ( u $hex:expr ) => {{
        use $crate::FromHex;
        $hex
            .from_hex()
            .map(|n| $crate::BigUint::from_bytes_be(&n))
            .unwrap()
    }};
    ( $hex:expr ) => {{
        use $crate::FromHex;
        $hex
            .from_hex()
            .map(|n| $crate::BigInt::from_bytes_be($crate::Sign::Plus, &n))
            .unwrap()
    }}
}

lazy_static! {
    pub static ref P: BigUint = hex_to_bigint!(u"
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff");
    pub static ref G: BigUint = BigUint::from(2u32);

    pub static ref TWO: BigUint = BigUint::from(2u32);
    pub static ref ONE: BigUint = BigUint::one();
    pub static ref ZERO: BigUint = BigUint::zero();
}


#[derive(Clone)]
pub struct DH {
    p: BigUint,
    s: BigUint,
    k: BigUint
}

impl Default for DH {
    fn default() -> DH {
        DH::new(&P, &G)
    }
}

#[macro_export]
macro_rules! rand_big {
    ( : $size:expr ) => {{
        use num::bigint::RandBigInt;
        $crate::thread_rng().gen_biguint($size)
    }};
    ( $start:expr, $end:expr ) => {{
        use num::bigint::RandBigInt;
        $crate::thread_rng().gen_biguint_range($start, $end)
    }};
    ( $end:expr ) => {
        rand_big!( &$crate::ZERO, $end )
    };
    () => {
        rand_big!( &$crate::P )
    }
}

impl DH {
    pub fn new(p: &BigUint, g: &BigUint) -> DH {
        DH::from(p, g, &rand_big!())
    }
    pub fn new_data(p: &[u8], g: &[u8]) -> DH {
        DH::new(
            &BigUint::from_bytes_be(p),
            &BigUint::from_bytes_be(g)
        )
    }
    pub fn from(p: &BigUint, g: &BigUint, s: &BigUint) -> DH {
        DH {
            p: p.clone(),
            s: s.clone(),
            k: modexp(g, s, p)
        }
    }
}

pub trait NumExchange {
    fn num_pk_gen(p: &BigUint, g: &BigUint, pk: &BigUint) -> (BigUint, BigUint);
    fn num_secret(&self) -> BigUint;
    fn num_public(&self) -> BigUint;
    fn num_exchange(&self, pk: &BigUint) -> BigUint;
}

impl NumExchange for DH {
    fn num_pk_gen(p: &BigUint, g: &BigUint, pk: &BigUint) -> (BigUint, BigUint) {
        let dh = DH::new(p, g);
        (dh.num_public(), dh.num_exchange(pk))
    }
    fn num_secret(&self) -> BigUint {
        self.s.clone()
    }
    fn num_public(&self) -> BigUint {
        self.k.clone()
    }
    fn num_exchange(&self, pk: &BigUint) -> BigUint {
        modexp(pk, &self.s, &self.p)
    }
}

pub fn modexp(base: &BigUint, exps: &BigUint, mods: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exps = exps.clone();
    let mut out = ONE.clone();

    while exps > *ZERO {
        if exps.clone() & ONE.clone() == ONE.clone() {
            out = out * base.clone() % mods.clone();
        }

        base = pow(base, 2);
        base = base % mods;
        exps = exps >> 1;
    }

    out
}


#[test]
fn test_dh() {
    let alice = DH::default();
    let bob = DH::default();

    assert_eq!(
        alice.num_exchange(&bob.num_public()),
        bob.num_exchange(&alice.num_public())
    );
}

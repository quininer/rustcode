use num::{ BigUint, BigInt, Integer, Zero, One };
use num::bigint::{ ToBigInt, ToBigUint };


lazy_static! {
    pub static ref ZERO: BigInt = BigInt::zero();
    pub static ref ONE: BigInt = BigInt::one();
}

#[macro_export]
macro_rules! try_opt {
    ( $r:expr ) => {
        match $r {
            Some(r) => r,
            None => return None
        }
    }
}

pub fn uinvmod(e: &BigUint, et: &BigUint) -> Option<BigUint> {
    invmod(
        &try_opt!(e.to_bigint()),
        &try_opt!(et.to_bigint())
    ).and_then(|u| u.to_biguint())
}

pub fn invmod(e: &BigInt, et: &BigInt) -> Option<BigInt> {
    let (gcd, c, _) = egcd(&e, &et);

    if gcd != ONE.clone() {
        None
    } else if c >= ZERO.clone() {
        Some(c)
    } else {
        Some(et + c)
    }
}

pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut r1, mut r2) = (a.clone(), b.clone());
    let (mut s1, mut s2) = (ZERO.clone(), ONE.clone());
    let (mut t1, mut t2) = (ONE.clone(), ZERO.clone());

    while r2 != ZERO.clone() {
        let (q, r3) = r1.div_mod_floor(&r2);
        r1 = r2;
        r2 = r3;

        let s3 = &s1 - &q * &s2;
        s1 = s2;
        s2 = s3;

        let t3 = &t1 - &q * &t2;
        t1 = t2;
        t2 = t3;
    }

    (r1, t1, s1)
}

#[test]
fn test_invmod() {
    assert_eq!(
        invmod(
            &BigInt::from(17),
            &BigInt::from(3120)
        ),
        Some(BigInt::from(2753))
    );
}

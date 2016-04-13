use num::{ BigUint, BigInt, Zero, One };
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
    ).to_biguint()
}

pub fn invmod(a: &BigInt, n: &BigInt) -> BigInt {
    let (mut x, _) = egcd(a, n);
    if x < *ZERO {
        x = x + n;
    }
    x % n
}

pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt) {
    if b.clone() == *ZERO {
        (ONE.clone(), ZERO.clone())
    } else {
        let q = a / b;
        let r = a % b;
        let (s, t) = egcd(b, &r);
        (t.clone(), s - q * t)
    }
}

#[test]
fn test_invmod() {
    assert_eq!(
        invmod(
            &BigInt::from(17),
            &BigInt::from(3120)
        ),
        BigInt::from(2753)
    );
}

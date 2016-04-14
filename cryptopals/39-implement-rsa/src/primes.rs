use num::{ BigUint, Integer };
use implement_diffie_hellman::{ modexp, ZERO, ONE, TWO };


pub const SMALL_PRIMES: [usize; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

pub fn gen_prime(size: usize) -> BigUint {
    loop {
        let p = rand_big!(: size);
        if is_prime(&p) { return p };
    }
}

pub fn is_prime(p: &BigUint) -> bool {
    if p.is_even() { return false };
    for &n in &SMALL_PRIMES {
        let n = BigUint::from(n);
        if p == &n { return true };
        if p.is_multiple_of(&n) { return false };
    }

    miller_rabin(p)
}

fn miller_rabin(p: &BigUint) -> bool {
    let (s, d) = rewrite(&(p - ONE.clone()));
    (0..5).all(|_| {
        let b = rand_big!(&TWO, &p);
        let mut v = modexp(&b, &d, &p);
        if v != ONE.clone() && v != p + ONE.clone() {
            let mut i = ZERO.clone();
            loop {
                v = modexp(&v, &TWO, &p);
                if v == p + ONE.clone() {
                    break
                } else if v == ONE.clone() || i == s.clone() - ONE.clone() {
                    return false
                }
                i = i + ONE.clone();
            }
        }
        true
    })
}

fn rewrite(n: &BigUint) -> (BigUint, BigUint) {
    let mut n = n.clone();
    let mut s = ZERO.clone();

    while n.is_even() {
        n = &n / TWO.clone();
        s = &s + ONE.clone();
    }
    (s, n)
}

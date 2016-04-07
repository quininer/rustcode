use std::num::Wrapping;


static mut SEED: Wrapping<u64> = Wrapping(0);

pub fn next(bits: usize) -> usize {
    unsafe {
        SEED = (SEED * Wrapping(0x5DEECE66D) + Wrapping(0xB)) & Wrapping((1 << 48) - 1);
        (SEED >> (48 - bits)).0 as usize
    }
}

pub fn next_int(n: usize) -> usize {
    if (n & !(n-1)) == n {
        n * next(31) >> 31
    } else {
        let mut bits;
        let mut val;
        loop {
            bits = next(31);
            val = bits % n;
            println!("{}", val);

            if bits - val + (n - 1) > 0 { break };
        }
        val
    }
}

pub fn set_seed(seed: u64) {
    unsafe {
        SEED = (Wrapping(seed) ^ Wrapping(0x5DEECE66D)) & Wrapping((1 << 48) - 1);
    }
}

#[test]
fn test() {
    set_seed(0);
    assert_eq!(unsafe { SEED.0 }, 25214903917);
    assert_eq!(next(31), 1569741360);
    assert_eq!(next_int(1000), 948);
    assert_eq!(next_int(1000), 29);
    set_seed(0);
    assert_eq!(next_int(1000), 360);
}

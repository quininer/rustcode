extern crate byteorder;
extern crate break_an_md4keyed_mac_using_length_extension;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use byteorder::{ LittleEndian, ReadBytesExt };
use implement_a_sha_1_keyed_mac::{ Digest, f, g, h };
use break_an_md4keyed_mac_using_length_extension::{
    MD4, H0, H1, H2, H3,
    round_1, le_to_bytes
};


pub fn bit(x: u32, i: u32) -> u32 { (x >> i) & 0x01 }
pub fn eql(x: u32, y: u32, n: u32) -> u32 { (bit(x, n-1) ^ bit(y, n-1)) << (n-1) }

pub fn rev_round_1(a0: u32, b0: u32, c0: u32, d0: u32, a1: u32, s: u32) -> u32 {
    a1.rotate_right(s)
        .wrapping_sub(a0)
        .wrapping_sub(f(b0, c0, d0))
}

pub fn rev_round_2(a0: u32, b0: u32, c0: u32, d0: u32, a1: u32, s: u32) -> u32 {
    a1.rotate_right(s)
        .wrapping_sub(0x5A827999)
        .wrapping_sub(a0)
        .wrapping_sub(g(b0, c0, d0))
}

pub fn rev_round_3(a0: u32, b0: u32, c0: u32, d0: u32, a1: u32, s: u32) -> u32 {
    a1.rotate_right(s)
        .wrapping_sub(0x6ED9EBA1)
        .wrapping_sub(a0)
        .wrapping_sub(h(b0, c0, d0))
}

pub fn bytes_to_le(mut message: &[u8]) -> Vec<u32> {
    let mut data = Vec::with_capacity(16);
    loop {
        data.push(match message.read_u32::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => break
        });
    }
    data
}

/// Single-Step Modification. It is easy to modify M such that the conditions in
/// round 1 hold. For example, m1 can be modified as :
///     d1 <- d1 ^ (d1,7 << 6) ^ ((d1,8 ^ a1,8) << 7) ^ ((d1,11 ^ a1,11) << 10)
///     m1 <- (d1 >> 7) - d0 - F(a1, b0, c0)
/// After simple-message modification, (M, M') is a collision with probability 2−25
/// by Table 6.
///
/// a1 | a1,7 = b0,7
/// d1 | d1,7 = 0   | d1,8 = a1,8   | d1,11 = a1,11
/// c1 | c1,7 = 1   | c1,8 = 1      | c1,11 = 0     | c1,26 = d1,26
pub fn crack_md4_correct(message: &[u8], state: (u32, u32, u32, u32)) -> Vec<u8> {
    let mut data = bytes_to_le(message);
    let (a0, b0, c0, d0) = state;

    let mut a1 = round_1(a0, b0, c0, d0, data[0], 3);
    a1 ^= eql(a1, b0, 7);
    data[0] = rev_round_1(a0, b0, c0, d0, a1, 3);

    let mut d1 = round_1(d0, a1, b0, c0, data[1], 7);
    d1 ^= (bit(d1, 6) << 6)
        ^ eql(d1, a1, 8)
        ^ eql(d1, a1, 11);
    data[1] = rev_round_1(d0, a1, b0, c0, d1, 7);

    le_to_bytes(&data)
}

pub fn gen_md4_collision() -> (Vec<u8>, Vec<u8>) {
    let message = crack_md4_correct(
        &rand!(64),
        (H0, H1, H2, H3)
    );
    let mut message2 = bytes_to_le(&message);

    loop {
        message2[1] ^= rand!(_);
        let message2 = le_to_bytes(&message2);

        if message2 != message && MD4::hash(&message) == MD4::hash(&message2) {
            return (message, message2);
        }
    }
}

#[test]
fn test_correct() {
    let message = le_to_bytes(&[
        0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee,
        0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f,
        0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8,
        0x45dd8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9
    ]);
    let message2 = crack_md4_correct(&message, (H0, H1, H2, H3));
    assert_eq!(message, message2);
    assert_eq!(
        MD4::hash(&message),
        MD4::hash(&message2)
    );
}

#[test]
fn test_collision() {
    let (m1, m2) = gen_md4_collision();
    assert!(m1 != m2);
    assert_eq!(
        MD4::hash(&m1),
        MD4::hash(&m2)
    );
}

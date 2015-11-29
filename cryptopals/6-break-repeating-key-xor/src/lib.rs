#![allow(dead_code, unused_variables, overflowing_literals)]

extern crate rustc_serialize;
extern crate fixed_xor;

use fixed_xor::{ xor, Error };

const M1: u8 = 0x5555555555555555; //binary: 0101...
const M2: u8 = 0x3333333333333333; //binary: 00110011..
const M4: u8 = 0x0f0f0f0f0f0f0f0f; //binary:  4 zeros,  4 ones ...
const M8: u8 = 0x00ff00ff00ff00ff; //binary:  8 zeros,  8 ones ...
const M16: u8 = 0x0000ffff0000ffff; //binary: 16 zeros, 16 ones ...
const M32: u8 = 0x00000000ffffffff; //binary: 32 zeros, 32 ones ...
const HFF: u8 = 0xffffffffffffffff; //binary: all ones
const H01: u8 = 0x0101010101010101; //the sum of 256 to the power of 0,1,2,3...

pub fn hamming_weight(x: u8) -> u8 {
    let x = (x & M1 ) + ((x >>  1) & M1); //put count of each  2 bits into those  2 bits
    let x = (x & M2 ) + ((x >>  2) & M2); //put count of each  4 bits into those  4 bits
    let x = (x & M4 ) + ((x >>  4) & M4); //put count of each  8 bits into those  8 bits
    // let x = (x & M8 ) + ((x >>  8) & M8 ); //put count of each 16 bits into those 16 bits
    // let x = (x & M16) + ((x >> 16) & M16); //put count of each 32 bits into those 32 bits
    // let x = (x & M32) + ((x >> 32) & M32); //put count of each 64 bits into those 64 bits
    x
}

/// ```
/// use break_repeating_key_xor::hamming_distance;
///
/// assert_eq!(
///     hamming_distance(
///         b"this is a test",
///         b"wokka wokka!!!"
///     ).ok(),
///     Some(37)
/// );
/// ```
pub fn hamming_distance(x: &[u8], y: &[u8]) -> Result<usize, Error> {
    if x.len() != y.len() {
        return Err(Error::LengthError);
    }

    Ok(
        x.iter().zip(y.iter())
            .map(|(n, m)| n ^ m)
            .map(hamming_weight)
            .fold(0, |sum, n| sum + n) as usize
    )
}

#[test]
fn it_works() {
    let path = "./examples/6.txt";

    //
}

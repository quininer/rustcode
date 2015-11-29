extern crate rustc_serialize;

use rustc_serialize::hex::{ FromHex, FromHexError };
use rustc_serialize::base64::{ STANDARD, ToBase64 };

pub fn hextob64(s: &str) -> Result<String, FromHexError> {
    Ok(try!(s.from_hex()).to_base64(STANDARD))
}

#[test]
fn it_works() {
    assert_eq!(
        hextob64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").ok(),
        Some(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))
    );
}

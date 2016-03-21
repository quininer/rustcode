extern crate rustc_serialize;

use std::convert::From;
use rustc_serialize::hex::{ FromHex, ToHex, FromHexError };


#[macro_export]
macro_rules! xor {
    ( $( $bytes:expr ),* ) => {{
        let mut list = Vec::new();
        $( list.push($bytes); )*
        let first = list.pop().unwrap();
        list.iter().fold(
            first.into(),
            |out, next|
                $crate::xor(&out, &next)
                    .unwrap()
        )
    }}
}

#[derive(Copy, Clone, Debug)]
pub enum Error {
    HexError(FromHexError),
    LengthError
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Error {
        Error::HexError(err)
    }
}

pub fn xor(x: &[u8], y: &[u8]) -> Result<Vec<u8>, Error> {
    if x.len() == y.len() {
        Ok(
            x.iter()
                .zip(y.iter())
                .map(|(n, m)| n ^ m)
                .collect()
        )
    } else {
        Err(Error::LengthError)
    }
}

pub fn xor_by(x: &[u8], y: u8) -> Vec<u8> {
    x.iter()
        .map(|x| x ^ y)
        .collect()
}

pub fn xor_by_hex(x: &str, y: &str) -> Result<String, Error> {
    xor(
        &try!(x.from_hex()),
        &try!(y.from_hex())
    ).map(|u| u.to_hex())
}


#[test]
fn it_works() {
    assert_eq!(
        xor_by_hex(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965"
        ).ok(),
        Some(String::from("746865206b696420646f6e277420706c6179"))
    );
}

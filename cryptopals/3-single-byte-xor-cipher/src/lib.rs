extern crate rustc_serialize;
extern crate fixed_xor;

use std::fs::File;
use std::path::Path;
use std::num::ParseFloatError;
use std::cmp::Ordering::Equal;
use std::collections::HashMap;
use std::io::{ Read, Error as IoError };
use rustc_serialize::hex::{ FromHex, FromHexError };
use fixed_xor::xor_by;


#[derive(Debug)]
pub enum Error {
    Hex(FromHexError),
    Io(IoError),
    Parse(Option<ParseFloatError>),
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Error {
        Error::Hex(err)
    }
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Error {
        Error::Io(err)
    }
}

impl From<ParseFloatError> for Error {
    fn from(err: ParseFloatError) -> Error {
        Error::Parse(Some(err))
    }
}

pub type FreqsMap = HashMap<u8, f64>;

pub fn read_freqsmap<P: AsRef<Path>>(path: P) -> Result<FreqsMap, Error> {
    let mut fmap = FreqsMap::new();

    let mut data = String::new();
    try!(try!(File::open(path)).read_to_string(&mut data));

    for mut s in data.lines()
        .filter(|s| !(s.starts_with("//") || s.is_empty()))
        .map(|s| s.split_whitespace())
    {
        let chr = try!(s.next().ok_or(Error::Parse(None)));
        let score = try!(s.next().ok_or(Error::Parse(None)));

        fmap.entry(
            *try!(try!(chr.from_hex()).first().ok_or(Error::Parse(None)))
        ).or_insert(try!(score.parse()));
    }

    Ok(fmap)
}

pub fn analyse_frequency(
    ciphertext: &[u8], freqsmap: &FreqsMap
) -> Vec<(u8, f64)> {
    let mut ff = (0..255)
        .map(|s: u8| (s, xor_by(ciphertext, s)))
        .map(|(s, x)| (s, x.iter().fold(
            0.0,
            |sum, n| sum + freqsmap.get(n).unwrap_or(&0.0)
        )))
        .collect::<Vec<(u8, f64)>>();

    ff.sort_by(|&(_, n), &(_, m)| m.partial_cmp(&n).unwrap_or(Equal));

    ff
}

pub fn xor_by_max(v: Vec<u8>, fmap: FreqsMap) -> Vec<u8> {
    xor_by(&v, analyse_frequency(&v, &fmap)[0].0)
}


#[test]
fn it_works() {
    use rustc_serialize::hex::FromHex;

    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    assert_eq!(
        String::from_utf8(xor_by_max(
            ciphertext.from_hex().unwrap(),
            read_freqsmap("./examples/english.txt").ok().unwrap()
        )).ok(),
        Some(String::from("Cooking MC\'s like a pound of bacon"))
    );
}

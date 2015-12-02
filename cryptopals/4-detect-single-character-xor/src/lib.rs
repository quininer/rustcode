extern crate rustc_serialize;
extern crate fixed_xor;
extern crate single_byte_xor_cipher;

use std::cmp::Ordering::Equal;
use fixed_xor::xor_by;
use single_byte_xor_cipher::{ analyse_frequency, FreqsMap };


pub fn analyse_from_vec(
    ciphertexts: Vec<Vec<u8>>, fmap: FreqsMap
) -> Vec<(u8, f64)> {
    ciphertexts.iter()
        .map(|c| analyse_frequency(c, fmap.clone())[0])
        .collect::<Vec<(u8, f64)>>()
}

pub fn xor_from_vec(ciphertexts: Vec<Vec<u8>>, fmap: FreqsMap) -> Vec<u8> {
    let mut tt = ciphertexts.iter()
        .zip(analyse_from_vec(ciphertexts.clone(), fmap).iter())
        .map(|(x, &(y, z))| (x.clone(), (y, z)))
        .collect::<Vec<(Vec<u8>, (u8, f64))>>();

    tt.sort_by(
        |&(_, (_, n)), &(_, (_, m))|
            m.partial_cmp(&n).unwrap_or(Equal)
    );

    let (t, (k, _)) = tt.first().unwrap().clone();

    xor_by(&t, k)
}


#[test]
fn it_works() {
    use std::fs::File;
    use std::io::Read;
    use rustc_serialize::hex::FromHex;
    use single_byte_xor_cipher::read_freqsmap;

    let path = "./examples/4.txt";
    let mut data = String::new();
    File::open(path).expect("read error.").read_to_string(&mut data).ok();

    let ciphertexts = data.lines()
        .map(|s| s.from_hex().ok().unwrap())
        .collect::<Vec<Vec<u8>>>();

    assert_eq!(
        String::from_utf8(xor_from_vec(
            ciphertexts,
            read_freqsmap("../3-single-byte-xor-cipher/examples/english.txt").ok().unwrap()
        )).ok(),
        Some(String::from("Now that the party is jumping\n"))
    );
}

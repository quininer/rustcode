extern crate rustc_serialize;
extern crate fixed_xor;

use fixed_xor::xor;
use std::collections::HashMap;

pub fn analyse_frequency(x: &[u8]) -> Vec<(u8, usize)> {
    let mut hmap = HashMap::new();
    for i in 0..x.len() {
        *hmap.entry(&x[i]).or_insert(0) += 1;
    }

    let mut y = hmap.iter()
        .map(|x| (**x.0, *x.1))
        .collect::<Vec<(u8, usize)>>();
    y.sort_by(|a, b| b.1.cmp(&a.1));

    y
}

pub fn xor_bymax(v: Vec<u8>) -> Vec<u8> {
    xor(
        &v,
        &vec![analyse_frequency(&v)[0].0; v.len()]
    ).expect("xor error.")
}

#[test]
fn it_works() {
    use rustc_serialize::hex::FromHex;

    let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    assert_eq!(
        String::from_utf8(xor_bymax(cipher.from_hex().unwrap())).ok(),
        Some(String::from("cOOKING\u{0}mc\u{7}S\u{0}LIKE\u{0}A\u{0}POUND\u{0}OF\u{0}BACON"))
    );
}

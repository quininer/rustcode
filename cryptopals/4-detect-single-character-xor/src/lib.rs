extern crate rustc_serialize;
extern crate fixed_xor;
extern crate single_byte_xor_cipher;

use rustc_serialize::hex::FromHex;
use single_byte_xor_cipher::xor_bymax;

pub fn xor_bymax_fromlist(list: Vec<&str>) -> Vec<Vec<u8>> {
    list.iter()
        .map(|p| xor_bymax(p.from_hex().expect("[u8] from hex error.")))
        .collect()
}

pub fn most_readable(list: Vec<Vec<u8>>) -> Vec<u8> {
    let mut readables = list.iter()
        .map(|s| s.iter().filter(|&x| 31 < *x && *x < 127).cloned().collect())
        .collect::<Vec<Vec<u8>>>();

    readables.sort_by(|x, y| y.len().cmp(&x.len()));
    readables.first().expect("list not first.").clone()
}

#[test]
fn it_works() {
    use std::io::Read;
    use std::fs::File;

    let path = "./examples/4.txt";

    let mut data = String::new();
    File::open(path).expect("read error.")
        .read_to_string(&mut data).ok();
    let bar = most_readable(xor_bymax_fromlist(data.split("\n").collect()));

    assert_eq!(
        String::from_utf8(bar).ok(),
        Some(String::from("nOWTHATTHEPARTYISJUMPING*"))
    );
}

extern crate rustc_serialize;
extern crate fixed_xor;

pub mod hamming;

use fixed_xor::{ xor, Error };

pub fn guess_key() {
    //
}

#[test]
fn it_works() {
    use std::io::Read;
    use std::fs::File;
    use rustc_serialize::base64::FromBase64;

    let path = "./examples/6.txt";
    let mut data = String::new();

    File::open(path).expect("read error.").read_to_string(&mut data).ok();
    data = data.replace("\n", "");

    let data = data.from_base64().unwrap();

    assert_eq!(
        hamming::guess_keysize(&data, 2..41).ok(),
        Some(29)
    )
}

extern crate pkcs7_padding_validation;
extern crate cbc_bitflipping_attacks;
extern crate implement_pkcs7_padding;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use pkcs7_padding_validation::unpksc7padding;
use cbc_bitflipping_attacks::{ Oracle, Cipher };


pub fn is_qualified(oracle: &Oracle, data: &[u8]) -> bool {
    unpksc7padding(&oracle.decrypt(&data), 16).is_ok()
}

pub fn crack_cbc_padding(data: &[u8], iv: &[u8], verify: Box<Fn(&[u8]) -> bool>) -> Vec<u8> {
    // TODO
    Vec::new()
}


#[test]
fn it_works() {
    use implement_pkcs7_padding::pkcs7padding;

    let input = include_str!("input.txt");
    let input: Vec<u8> = rand!(choose input.lines()).into();
    let iv = rand!();
    let oracle = Oracle::new(&iv);

    let ciphertext = oracle.encrypt(&pkcs7padding(&input, 16));
    assert!(is_qualified(&oracle, &ciphertext));
    assert_eq!(
        crack_cbc_padding(
            &ciphertext,
            &iv,
            Box::new(move |u| is_qualified(&oracle, u))
        ),
        input
    );
}

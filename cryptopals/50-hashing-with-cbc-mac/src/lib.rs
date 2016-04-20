extern crate rustc_serialize;
extern crate cbc_mac_message_forgery;
extern crate implement_pkcs7_padding;
#[macro_use] extern crate fixed_xor;

use implement_pkcs7_padding::pkcs7padding;
use cbc_mac_message_forgery::aescbc_mac;


pub fn aescbc_hash(data: &[u8]) -> Vec<u8> {
    aescbc_mac(b"YELLOW SUBMARINE", &[0; 16], data)
}

pub fn crack_aescbchash_collide(content: &[u8], fake_content: &[u8]) -> Vec<u8> {
    let hash = aescbc_hash(fake_content);
    let fake_content_pad = pkcs7padding(fake_content, 16);
    [
        fake_content_pad,
        xor!(content[..16].into(), hash),
        content[16..].into()
    ].concat()
}


#[test]
fn it_works() {
    use rustc_serialize::hex::ToHex;

    let content = b"alert('MZA who was that?');\n";

    assert_eq!(
        aescbc_hash(content).to_hex(),
        "296b8d7cb78a243dda4d0a61d33bbdd1"
    );

    let fake_content = b"alert('Ayo, the Wu is back!'); //";
    let out = crack_aescbchash_collide(content, fake_content);
    assert_eq!(aescbc_hash(&out), aescbc_hash(content));
    assert!(out.starts_with(fake_content));
}

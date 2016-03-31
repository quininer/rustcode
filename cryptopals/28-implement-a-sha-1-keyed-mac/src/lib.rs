#![feature(question_mark)]

extern crate rustc_serialize;
extern crate byteorder;

mod sha1;

pub use byteorder::{ BigEndian, LittleEndian };
pub use sha1::{ Sha1, Digest, padding };


pub fn concat_mac<H: Digest>(key: &[u8], message: &[u8]) -> Vec<u8> {
    H::hash(&[key, message].concat())
}

pub fn sha1_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    concat_mac::<Sha1>(key, message)
}

#[test]
fn it_works() {
    use rustc_serialize::hex::FromHex;

    let key = b"SHA1";
    let data = b"US Secure Hash Algorithm 1";

    assert_eq!(
        Sha1::hash(b""),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709".from_hex().unwrap()
    );
    assert_eq!(
        Sha1::hash(data),
        "fa1c3caec16f37de47773e7ad1e7e02f715e1960".from_hex().unwrap()
    );
    assert_eq!(
        Sha1::hash(b"These are examples of SHA-1 message digests in hexadecimal and in Base64 binary to ASCII text encoding."),
        "15c76290347bb83fd94029fbe82318a3b62bda0f".from_hex().unwrap()
    );
    assert_eq!(
        Sha1::hash(&[0; 40]),
        "b80de5d138758541c5f05265ad144ab9fa86d1db".from_hex().unwrap()
    );

    assert!(sha1_mac(key, data) == sha1_mac(key, data));
    assert!(!(sha1_mac(key, data) == sha1_mac(key, key)));
    assert!(!(sha1_mac(key, data) == sha1_mac(data, data)));
}

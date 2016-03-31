#![feature(question_mark)]

extern crate byteorder;
extern crate rustc_serialize;
extern crate implement_a_sha_1_keyed_mac;

mod md4;

use std::io;
use byteorder::LittleEndian;
use implement_a_sha_1_keyed_mac::{ concat_mac, Digest, padding };
pub use md4::MD4;


pub fn md4_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    concat_mac(&mut MD4::new(), key, message)
}

pub fn crack_md4mac_append(
    ks: usize,
    hash: &[u8],
    message: &[u8],
    append: &[u8]
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut md4 = MD4::from(hash)?;
    let pad = &padding::<LittleEndian>(&[&vec![0; ks], message].concat(), 0)?[ks+message.len()..];
    md4.process(&padding::<LittleEndian>(append, ks+message.len()+pad.len())?);

    Ok((
        md4.digest(),
        [message, pad, append].concat()
    ))
}


#[test]
fn it_works() {
    let key = b"1234567890123456";
    let message = b"Break an MD4 keyed MAC using";
    let hash = md4_mac(key, message);
    let (hash, message) = crack_md4mac_append(
        key.len(),
        &hash,
        message,
        b" length extension"
    ).unwrap();
    assert_eq!(
        md4_mac(key, &message),
        hash
    );
}

#![feature(question_mark)]

extern crate implement_a_sha_1_keyed_mac;
extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use std::io;
use implement_a_sha_1_keyed_mac::{
    Sha1, Digest,
    sha1_mac, padding,
    BigEndian
};
use cbc_bitflipping_attacks::postdata;


pub fn sha1mac_postdata(key: &[u8], input: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let out: Vec<u8> = postdata(input).into();
    (sha1_mac(key, &out), out)
}

pub fn sha1mac_is_admin(key: &[u8], hash: &[u8], message: &[u8]) -> bool {
    sha1_mac(key, message) == hash
        && String::from_utf8_lossy(message).contains(";admin=true;")
}

pub fn crack_sha1mac_append(
    ks: usize,
    hash: &[u8],
    message: &[u8],
    append: &[u8]
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut sha1 = Sha1::from(hash)?;
    let pad = &padding::<BigEndian>(&[&vec![0; ks], message].concat(), 0)?[ks+message.len()..];
    sha1.process(&padding::<BigEndian>(append, ks+message.len()+pad.len())?);

    Ok((
        sha1.digest(),
        [message, pad, append].concat()
    ))
}


#[test]
fn it_works() {
    let key = rand!(rand!(choose 5..40));
    let (hash, message) = sha1mac_postdata(&key, b"ooh");
    assert!(!sha1mac_is_admin(
        &key,
        &hash,
        &message
    ));
    assert!(sha1mac_is_admin(
        &key,
        &sha1_mac(&key, b"xxx;admin=true;"),
        b"xxx;admin=true;"
    ));

    let ks = (5..40).find(|&r| {
        let (fake_hash, fake_message) = crack_sha1mac_append(
            r,
            &hash,
            &message,
            b"xxx;admin=true;"
        ).unwrap();
        sha1mac_is_admin(&key, &fake_hash, &fake_message)
    }).unwrap();

    assert_eq!(key.len(), ks);
}

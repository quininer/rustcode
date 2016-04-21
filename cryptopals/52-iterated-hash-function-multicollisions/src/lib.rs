extern crate num;
extern crate openssl;
extern crate implement_and_break_hmac_sha1_with_an_artificial_timing_leak;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use std::collections::HashMap;
use num::BigUint;
use openssl::crypto::symm::{ Crypter, Type, Mode };
use implement_and_break_hmac_sha1_with_an_artificial_timing_leak::rightpad;


pub const H: usize = 4;
pub type CompressFn = Box<Fn(&[u8], &[u8]) -> Vec<u8>>;

pub fn aes_hash(data: &[u8], state: &[u8]) -> Vec<u8> {
    let aes = Crypter::new(Type::AES_128_ECB);
    aes.init(Mode::Encrypt, &rightpad(state, 16), &[]);
    [
        aes.update(&rightpad(data, 16)),
        aes.finalize()
    ].concat()[..H].into()
}

pub fn padding(data: &[u8]) -> Vec<u8> {
    rightpad(data, H)
}

pub fn md_aes(message: &[u8], is: &[u8]) -> Vec<u8> {
    let mut is: Vec<u8> = padding(is)[..H].into();
    let message = padding(message);
    for b in message.chunks(H) {
        is = aes_hash(b, &is);
    }
    is
}

pub fn crack_md_preimage_collide(message: &[u8], prefix: &[u8], md: CompressFn) -> Result<Vec<u8>, ()> {
    let message = padding(message);
    let prefix = padding(prefix);
    let state = md(&prefix, &[]);

    let mut preimage = HashMap::new();
    let mut is = vec![0; H];
    for (pos, b) in message.chunks(H).enumerate() {
        let state = md(&b, &is);
        preimage.insert(state.clone(), pos);
        is = state;
    }

    match (0..::std::usize::MAX)
        .map(BigUint::from)
        .map(|n| padding(&n.to_bytes_be()))
        .find(|u| preimage.get(&md(&u, &state)).is_some())
    {
        Some(out) => {
            let pos = preimage.get(&md(&out, &state)).unwrap() * H;
            Ok([
                &prefix,
                &out,
                &message[pos+H..]
            ].concat())
        },
        None => Err(())
    }
}


#[test]
fn test_preimage() {
    let message = rand!(H * 10);
    let fake_message = b"fake message. //";
    let fake_message = crack_md_preimage_collide(
        &message,
        fake_message,
        Box::new(md_aes)
    ).unwrap();

    assert_eq!(
        md_aes(&message, &[]),
        md_aes(&fake_message, &[])
    );
}

#[test]
fn it_works() {
    let mut collisions = HashMap::new();
    let mut x = "hello world.".into();
    let mut y = "hello world!".into();
    for b in (0..2usize.pow(H as u32 * 8))
        .map(BigUint::from)
        .map(|n| n.to_bytes_be())
    {
        match collisions.insert(md_aes(&b, &[]), b.clone()) {
            Some(out) => {
                x = out;
                y = b;
                break
            },
            None => ()
        };
    }
    assert_eq!(
        md_aes(&x, &[]),
        md_aes(&y, &[])
    );

    // TODO vapidity
}

#[test]
fn test_md_aes() {
    assert_eq!(
        md_aes(b"hello world.", &[]),
        md_aes(b"hello world.", &[])
    );
    assert!(
        md_aes(b"hello world.", &[])
        !=
        md_aes(b"hello world!", &[])
    )
}

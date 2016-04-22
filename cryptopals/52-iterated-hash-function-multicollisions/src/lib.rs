extern crate num;
extern crate openssl;
extern crate implement_diffie_hellman;
extern crate implement_and_break_hmac_sha1_with_an_artificial_timing_leak;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use std::collections::HashMap;
use num::{ pow, range };
use openssl::crypto::symm::{ Crypter, Type, Mode };
use implement_and_break_hmac_sha1_with_an_artificial_timing_leak::rightpad;
use implement_diffie_hellman::{ ZERO, TWO };


pub const H: usize = 8;
pub type HashFn = Box<Fn(&[u8], &[u8]) -> Vec<u8>>;

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

/*
pub fn crack_md_preimage_collide(message: &[u8], prefix: &[u8], md: HashFn) -> Result<Vec<u8>, ()> {
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
*/

pub fn gen_collide(h: usize, md: HashFn, is1: &[u8], is2: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut collisions: HashMap<Vec<u8>,Vec<u8>> = HashMap::new();
    for b in range(ZERO.clone(), pow(TWO.clone(), h * 8)) {
        let b = b.to_bytes_be();
        if let Some(a) = collisions.get(&md(&b, is2)) {
            return Ok((a.clone(), b));
        }

        collisions.insert(md(&b, is1), b);
    }
    Err(())
}

/*
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
*/

#[test]
fn it_works() {
    let (x, y) = gen_collide(H, Box::new(md_aes), &[], &[]).unwrap();
    assert!(x != y);
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

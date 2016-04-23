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


pub const H: usize = 2;
pub const B: usize = 16;
pub type HashFn = Box<Fn(&[u8], &[u8]) -> Vec<u8>>;

pub fn aes_hash(data: &[u8], state: &[u8]) -> Vec<u8> {
    let aes = Crypter::new(Type::AES_128_ECB);
    aes.init(Mode::Encrypt, &rightpad(state, B), &[]);
    [
        aes.update(&rightpad(data, B)),
        aes.finalize()
    ].concat()[..H].into()
}

pub fn md_aes(message: &[u8], is: &[u8]) -> Vec<u8> {
    let mut is: Vec<u8> = rightpad(is, H)[..H].into();
    let message = rightpad(message, B);
    for b in message.chunks(B) {
        is = aes_hash(b, &is);
    }
    is
}

pub fn gen_collide(h: usize, md: HashFn) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut collisions: HashMap<Vec<u8>,Vec<u8>> = HashMap::new();
    for b in range(ZERO.clone(), pow(TWO.clone(), h * 8)) {
        let b = rightpad(&b.to_bytes_le(), B);
        if let Some(a) = collisions.get(&md(&b, &[])) {
            return Ok((a.clone(), b));
        }

        collisions.insert(md(&b, &[]), b);
    }
    Err(())
}


#[test]
fn it_works() {
    let (x, y) = gen_collide(H, Box::new(md_aes)).unwrap();
    assert!(x != y);
    assert_eq!(md_aes(&x, &[]), md_aes(&y, &[]));

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

#![feature(question_mark)]

extern crate time;
extern crate hyper;
extern crate rustc_serialize;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate rouille;
#[macro_use] extern crate maplit;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

mod hmac;
#[macro_use] mod http;

use rustc_serialize::hex::ToHex;
use time::{ PreciseTime, Duration };
pub use hmac::{ hmac, hmac_sha1 };
pub use http::{ hmac_app, INTERVAL };


pub fn rightpad(data: &[u8], len: usize) -> Vec<u8> {
    [
        data.into(),
        vec![0; len-data.len()]
    ].concat()
}

pub fn check(f: &[u8], u: &[u8]) -> bool {
    request!(&format!(
        "http://127.0.0.1:8000/test/{}/{}",
        String::from_utf8_lossy(f),
        u.to_hex()
    ))
}

pub fn crack_hmac_app(
    len: usize,
    num: usize,
    check: Box<Fn(&[u8]) -> bool>
) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..len {
        let byte = (0..std::u8::MAX as usize+1).map(|u| (
            (0..num).map(|_| {
                let start = PreciseTime::now();
                check(&rightpad(&[
                    out.clone(),
                    vec![u as u8]
                ].concat(), 20));
                let end = PreciseTime::now();
                start.to(end)
            }).fold(Duration::zero(), |out, next| out + next),
            u as u8
        ))
            .max()
            .unwrap()
            .1;
        out.push(byte);
    }
    out
}


#[test]
fn it_works() {
    use std::thread::spawn;
    use rouille::start_server;

    spawn(|| start_server("127.0.0.1:8000", hmac_app));

    let crack_file = b"bad";
    let crack_hash = crack_hmac_app(
        20,
        1,
        Box::new(move |u| check(crack_file, u))
    );

    assert!(check(crack_file, &crack_hash));
}

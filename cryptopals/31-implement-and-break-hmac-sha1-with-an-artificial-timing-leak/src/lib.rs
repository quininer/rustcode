#![feature(question_mark)]

extern crate hyper;
extern crate rustc_serialize;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate rouille;
#[macro_use] extern crate maplit;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

mod hmac;
mod http;

pub use hmac::{ hmac, hmac_sha1 };
pub use http::hmac_app;



#[test]
fn it_works() {
}

extern crate implement_the_mt19937_mersenne_twister_rng;
extern crate implement_ctr_the_stream_cipher_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

use implement_the_mt19937_mersenne_twister_rng::MT19937;
use implement_ctr_the_stream_cipher_mode::StreamCipher;


#[test]
fn it_works() {
    let key: u16 = rand!(x);
    let known_plaintext = b"AAAAAAAAAAAAAA";
}

#[test]
fn test_mt_stream_cipher() {
    let key: u16 = rand!(x);
    let data = rand!();
    assert_eq!(
        data,
        MT19937::new(key as u32)
            .update(&MT19937::new(key as u32).update(&data))
    );
}

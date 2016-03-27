extern crate time;
extern crate implement_the_mt19937_mersenne_twister_rng;
extern crate implement_ctr_the_stream_cipher_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

use implement_the_mt19937_mersenne_twister_rng::MT19937;
use implement_ctr_the_stream_cipher_mode::StreamCipher;


#[test]
fn it_works() {
    let key: u16 = rand!(x);
    let mut mt_cipher = MT19937::new(key as u32);
    let known_plaintext = b"AAAAAAAAAAAAAA";
    let ciphertext = mt_cipher.update(&[
        rand!(rand!(choose 5..40)),
        known_plaintext.to_vec()
    ].concat());

    let guess_key = (0..std::u16::MAX as usize + 1).find(|&k|
        MT19937::new(k as u32)
            .take(ciphertext.len())
            .skip(ciphertext.len() - known_plaintext.len())
            .zip(known_plaintext.iter())
            .map(|(k, p)| k as u8 ^ p)
            .collect::<Vec<_>>()
        ==
        ciphertext[ciphertext.len() - known_plaintext.len()..].to_vec()
    ).map(|r| r as u16);

    assert_eq!(Some(key), guess_key);
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

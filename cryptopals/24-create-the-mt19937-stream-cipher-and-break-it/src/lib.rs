extern crate time;
extern crate implement_the_mt19937_mersenne_twister_rng;
extern crate implement_ctr_the_stream_cipher_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

use implement_the_mt19937_mersenne_twister_rng::MT19937;


pub struct Token(u32);

impl Token {
    pub fn get(&self) -> Vec<u8> {
        MT19937::new(self.0)
            .take(16)
            .map(|r| r as u8)
            .collect()
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        self.get() == data
    }
}


#[test]
fn test_token() {
    use time::get_time;

    let token = Token(get_time().sec as u32);

    let now = get_time().sec as u32;
    let seed = (now-1500..now+1500).find(|&u| token.verify(
        &MT19937::new(u)
            .take(16)
            .map(|r| r as u8)
            .collect::<Vec<_>>()
    )).unwrap();

    assert!(token.verify(
        &MT19937::new(seed)
            .take(16)
            .map(|r| r as u8)
            .collect::<Vec<_>>()
    ));
}

#[test]
fn test_crack_mt_mtream_cipher() {
    use implement_ctr_the_stream_cipher_mode::StreamCipher;

    let key: u16 = rand!(_);
    let mut mt_cipher = MT19937::new(key as u32);
    let known_plaintext = b"AAAAAAAAAAAAAA";
    let ciphertext = mt_cipher.update(&[
        rand!(rand!(choose 5..40)),
        known_plaintext.to_vec()
    ].concat());

    let guess_key = (0..std::u16::MAX as usize + 1)
        .map(|r| r as u16)
        .find(|&k|
            MT19937::new(k as u32)
                .take(ciphertext.len())
                .skip(ciphertext.len() - known_plaintext.len())
                .zip(known_plaintext.iter())
                .map(|(k, p)| k as u8 ^ p)
                .collect::<Vec<_>>()
            ==
            &ciphertext[ciphertext.len() - known_plaintext.len()..]
        );

    assert_eq!(guess_key, Some(key));
}

#[test]
fn test_mt_stream_cipher() {
    use implement_ctr_the_stream_cipher_mode::StreamCipher;

    let key: u16 = rand!(_);
    let data = rand!();
    assert_eq!(
        data,
        MT19937::new(key as u32)
            .update(&MT19937::new(key as u32).update(&data))
    );
}

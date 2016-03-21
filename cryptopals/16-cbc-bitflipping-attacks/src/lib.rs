extern crate implement_cbc_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

use std::ops::Range;
use implement_cbc_mode::{ AesCBC, Mode };


pub struct Oracle {
    key: Vec<u8>,
    iv: Vec<u8>
}

impl Oracle {
    pub fn new() -> Oracle  {
        Oracle { key: rand!(16), iv: rand!(16) }
    }
}

pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

impl Cipher for Oracle {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        AesCBC::new(&self.key, &self.iv).update(Mode::Encrypt, data)
    }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        AesCBC::new(&self.key, &self.iv).update(Mode::Decrypt, data)
    }
}

pub fn postdata<D: AsRef<[u8]>>(input: D) -> String {
    format!(
        "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon",
        String::from_utf8_lossy(input.as_ref())
            .replace(';', "%3b")
            .replace('=', "%3d")
    )
}

/// ```
/// use cbc_bitflipping_attacks::{ Oracle, Cipher, is_admin };
/// let oracle = Oracle::new();
/// let input = oracle.encrypt(b"xxxxx;admin=true;xxxx");
/// assert!(is_admin(&oracle, &input));
/// ```
pub fn is_admin(oracle: &Oracle, input: &[u8]) -> bool {
    String::from_utf8_lossy(&oracle.decrypt(input))
        .contains(";admin=true;")
}

pub fn crack_replace(plain: &[u8], cipher: &[u8], range: Range<usize>, text: &[u8]) -> Vec<u8> {
    assert!(
        cipher.len() >= 32
            && plain.len() >= range.end
            && cipher.len() >= range.end
            && range.end - range.start == text.len()
    );

    [
        cipher[..range.start-16].to_vec(),
        xor!(
            &cipher[range.start-16..range.end-16],
            &plain[range.clone()],
            text
        ),
        cipher[range.end-16..].to_vec()
    ].concat()
}


#[test]
fn it_works() {
    let oracle = Oracle::new();
    let text = postdata([b'x'; 32]);
    let ciphertext = oracle.encrypt(&text.as_ref());
    let cracktext = crack_replace(
        &text.as_ref(),
        &ciphertext,
        48..64,
        b"xxxxx;admin=true"
    );
    assert!(is_admin(&oracle, &cracktext));
}

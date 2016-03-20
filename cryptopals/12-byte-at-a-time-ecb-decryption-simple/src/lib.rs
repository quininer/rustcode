extern crate rand;
extern crate openssl;
extern crate rustc_serialize;
extern crate detect_aes_in_ecb_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use rand::{ thread_rng, Rng };
use openssl::crypto::symm::{ Crypter, Type, Mode };


pub struct Oracle {
    prefix: Vec<u8>,
    key: Vec<u8>,
    suffix: Vec<u8>
}

/// ```
/// use byte_at_a_time_ecb_decryption_simple::Oracle;
/// let oracle = Oracle::new(&[], &[]);
/// let data = b"byte_at_a_time_ecb_decryption_simple::Oracle;";
///
/// assert_eq!(
///     oracle.decryption(&oracle.encryption(data)),
///     data.to_vec()
/// )
/// ```
impl Oracle {
    pub fn new(prefix: &[u8], suffix: &[u8]) -> Oracle {
        Oracle {
            prefix: prefix.into(),
            key: rand!(),
            suffix: suffix.into()
        }
    }

    pub fn encryption(&self, data: &[u8]) -> Vec<u8> {
        let ecb = Crypter::new(Type::AES_128_ECB);
        ecb.init(Mode::Encrypt, &self.key, &[]);
        ecb.pad(true);
        let d = [
            self.prefix.as_ref(),
            data,
            self.suffix.as_ref()
        ].concat();
        [ecb.update(&d), ecb.finalize()].concat()
    }

    pub fn decryption(&self, data: &[u8]) -> Vec<u8> {
        let ecb = Crypter::new(Type::AES_128_ECB);
        ecb.init(Mode::Decrypt, &self.key, &[]);
        ecb.pad(true);
        [ecb.update(data), ecb.finalize()].concat()
    }
}

pub fn crack_blocksize(oracle: &Oracle) -> (usize, usize) {
    let l = oracle.encryption(&[]).len();
    let mut p = 1;
    loop {
        let pd = oracle.encryption(&vec![0; p]).len();
        if pd != l {
            return (pd - l, p);
        }
        p += 1;
    }
}

pub fn crack_nextbyte((offset, i): (usize, usize), bs: usize, known: &[u8], oracle: &Oracle) -> Option<u8> {
    let padding = vec![0; i + bs - (known.len() % bs) - 1];
    let pbs = offset - i + padding.len() + known.len() + 1;
    let paddinged = oracle.encryption(&padding);
    if paddinged.len() <= pbs {
        return None;
    }
    (0..std::u8::MAX).find(
        |u| &paddinged[offset..pbs] == &oracle.encryption(&[
            padding.as_ref(),
            known,
            &[*u]
        ].concat())[offset..pbs]
    )
}

pub fn crack_plaintext(offset: (usize, usize), bs: usize, oracle: &Oracle) -> Vec<u8> {
    let mut known = Vec::new();
    loop {
        match crack_nextbyte(offset, bs, &known.clone(), oracle) {
            Some(b) => known.push(b),
            None => break
        }
    }
    known
}

#[test]
fn it_works() {
    use detect_aes_in_ecb_mode::repetition_rate;
    use rustc_serialize::base64::FromBase64;

    let data = include_str!("input.txt");
    let data = data.from_base64().unwrap();

    let oracle = Oracle::new(&[], &data);
    let (bs, _) = crack_blocksize(&oracle);

    let _ = if repetition_rate(
        &oracle.encryption(&vec![0; bs * (&oracle.encryption(b"").len() / bs) * 4]),
        bs
    ) > 0.5 { Type::AES_128_ECB } else { panic!() };

    assert_eq!(
        data,
        crack_plaintext((0, 0), bs, &oracle)
    )
}

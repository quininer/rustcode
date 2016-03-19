extern crate rand;
extern crate openssl;
extern crate rustc_serialize;
extern crate detect_aes_in_ecb_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use rand::{ thread_rng, Rng };
use openssl::crypto::symm::{ Crypter, Type, Mode };

pub struct Oracle {
    key: Vec<u8>,
    data: Vec<u8>
}

/// ```
/// use byte_at_a_time_ecb_decryption_simple::Oracle;
/// let oracle = Oracle::new(&[]);
/// let data = b"byte_at_a_time_ecb_decryption_simple::Oracle;";
///
/// assert_eq!(
///     oracle.decryption(&oracle.encryption(data)),
///     data.to_vec()
/// )
/// ```
impl Oracle {
    pub fn new(data: &[u8]) -> Oracle {
        Oracle {
            key: rand!(),
            data: data.into()
        }
    }

    pub fn encryption(&self, data: &[u8]) -> Vec<u8> {
        let ecb = Crypter::new(Type::AES_128_ECB);
        ecb.init(Mode::Encrypt, &self.key, &[]);
        ecb.pad(true);
        let d = [data, self.data.as_ref()].concat();
        [ecb.update(&d), ecb.finalize()].concat()
    }

    pub fn decryption(&self, data: &[u8]) -> Vec<u8> {
        let ecb = Crypter::new(Type::AES_128_ECB);
        ecb.init(Mode::Decrypt, &self.key, &[]);
        ecb.pad(true);
        [ecb.update(data), ecb.finalize()].concat()
    }
}

pub fn crack_blocksize(oracle: &Oracle) -> usize {
    let l = oracle.encryption(b"").len();
    let mut i = 1;
    loop {
        let s = oracle.encryption(&vec![0; i]).len();
        if s != l {
            return s - l;
        }
        i += 1;
    }
}

pub fn crack_nextbyte(blocksize: usize, known: &[u8], oracle: &Oracle) -> Result<u8, ()> {
    let padding = vec![0; blocksize - (known.len() % blocksize) - 1];
    let bs = padding.len() + known.len() + 1;
    let paddinged = oracle.encryption(&padding);
    if paddinged.len() <= bs {
        return Err(());
    }
    for u in 0..std::u8::MAX {
        if &paddinged[..bs] == &oracle.encryption(&[
            padding.as_ref(),
            known,
            vec![u].as_ref()
        ].concat())[..bs] {
            return Ok(u);
        }
    }
    Err(())
}

pub fn crack_plaintext(blocksize: usize, oracle: &Oracle) -> Vec<u8> {
    let mut known = Vec::new();
    loop {
        match crack_nextbyte(blocksize, &known.clone(), oracle) {
            Ok(b) => known.push(b),
            Err(_) => break
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

    let oracle = Oracle::new(&data);
    let blocksize = crack_blocksize(&oracle);

    let _ = if repetition_rate(
        &oracle.encryption(&vec![0; blocksize * (&oracle.encryption(b"").len() / blocksize) * 4]),
        blocksize
    ) > 0.5 { Type::AES_128_ECB } else { panic!() };

    assert_eq!(
        data,
        crack_plaintext(blocksize, &oracle)
    )
}

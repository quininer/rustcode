extern crate openssl;
extern crate rustc_serialize;
extern crate detect_aes_in_ecb_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use openssl::crypto::symm::{ Crypter, Type, Mode };


pub type Encryptor = Box<Fn(&[u8]) -> Vec<u8>>;

#[derive(Clone)]
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
///     oracle.decrypt(&oracle.encrypt(data)),
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

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
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

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let ecb = Crypter::new(Type::AES_128_ECB);
        ecb.init(Mode::Decrypt, &self.key, &[]);
        ecb.pad(true);
        [ecb.update(data), ecb.finalize()].concat()
    }
}

pub fn crack_ecb_blocksize(encryptor: Encryptor) -> (usize, usize) {
    let l = encryptor(&[]).len();
    let mut p = 1;
    loop {
        let pd = encryptor(&vec![0; p]).len();
        if pd != l {
            return (pd - l, p);
        }
        p += 1;
    }
}

pub fn crack_ecb_nextbyte((offset, i): (usize, usize), bs: usize, known: &[u8], encryptor: &Encryptor) -> Option<u8> {
    let padding = vec![0; i + bs - (known.len() % bs) - 1];
    let pbs = offset - i + padding.len() + known.len() + 1;
    let paddinged = encryptor(&padding);
    if paddinged.len() <= pbs {
        return None;
    }
    (0..std::u8::MAX as usize + 1).map(|r| r as u8).find(
        |&u| &paddinged[offset..pbs] == &encryptor(&[
            padding.as_ref(),
            known,
            &[u]
        ].concat())[offset..pbs]
    )
}

pub fn crack_ecb_plaintext(offset: (usize, usize), bs: usize, encryptor: Encryptor) -> Vec<u8> {
    let mut known = Vec::new();
    while let Some(b) = crack_ecb_nextbyte(offset, bs, &known.clone(), &encryptor) {
        known.push(b);
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
    let oracle_encrypt = oracle.clone();
    let (bs, _) = crack_ecb_blocksize(Box::new(move |u| oracle_encrypt.encrypt(u)));

    let _ = if repetition_rate(
        &oracle.encrypt(&vec![0; bs * (&oracle.encrypt(b"").len() / bs) * 4]),
        bs
    ) > 0.5 { Type::AES_128_ECB } else { panic!() };

    assert_eq!(
        data,
        crack_ecb_plaintext((0, 0), bs, Box::new(move |u| oracle.encrypt(u)))
    );
}

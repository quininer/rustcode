extern crate rustc_serialize;
extern crate openssl;
extern crate fixed_xor;

pub use openssl::crypto::symm::Mode;
use openssl::crypto::symm::{ Crypter, Type };
use fixed_xor::xor;


#[derive(Clone, Debug)]
pub struct AesCBC {
    key: Vec<u8>,
    iv: Vec<u8>
}

impl AesCBC {
    pub fn new(key: &[u8], iv: &[u8]) -> AesCBC {
        AesCBC { key: key.to_vec(), iv: iv.to_vec() }
    }

    pub fn set_iv(&mut self, iv: &[u8]) {
        self.iv = iv.to_vec();
    }

    pub fn update(&mut self, mode: Mode, data: &[u8]) -> Vec<u8> {
        let crypter = Crypter::new(Type::AES_128_ECB);
        crypter.init(mode, &self.key, &[]);
        crypter.pad(false);
        data.chunks(self.key.len())
            .map(|u| match mode {
                Mode::Encrypt => {
                    let text = crypter.update(&xor(
                        &u,
                        &self.iv
                    ).unwrap());
                    self.set_iv(&text);
                    text
                },
                Mode::Decrypt => {
                    let iv = self.iv.clone();
                    self.set_iv(u);
                    xor(
                        &crypter.update(&u),
                        &iv
                    ).unwrap()
                }
            })
            .collect::<Vec<Vec<u8>>>()
            .concat()
    }
}


#[test]
fn it_works() {
    use std::fs::File;
    use std::io::Read;
    use rustc_serialize::base64::FromBase64;

    let mut data = String::new();
    let key = b"YELLOW SUBMARINE";
    let iv = &vec![0; key.len()];

    File::open("./examples/10.txt").expect("read error.")
        .read_to_string(&mut data).ok();
    let data = data.from_base64().unwrap();

    let mut aescbc = AesCBC::new(key, iv);
    let plaintext = aescbc.update(Mode::Decrypt, &data);

    aescbc.set_iv(iv);

    assert_eq!(
        aescbc.update(Mode::Encrypt, &plaintext),
        data
    );
}

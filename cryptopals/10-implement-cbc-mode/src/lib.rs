extern crate rustc_serialize;
extern crate openssl;
extern crate fixed_xor;
extern crate implement_pkcs7_padding;

use openssl::crypto::symm::{ Crypter, Type, Mode };
use fixed_xor::xor;
use implement_pkcs7_padding::pksc7padding;

pub struct AesCBC {
    key: Vec<u8>,
    iv: Vec<u8>
}

impl AesCBC {
    pub fn new(key: Vec<u8>, iv: Vec<u8>) -> AesCBC {
        AesCBC { key: key, iv: iv }
    }

    pub fn set_iv(&mut self, iv: &[u8]) {
        self.iv = iv.to_vec();
    }

    pub fn update(&mut self, mode: Mode, data: &[u8]) -> Vec<u8> {
        let crypter = Crypter::new(Type::AES_128_ECB);
        crypter.init(mode, &self.key, &Vec::new());
        crypter.pad(false);
        data.chunks(self.key.len())
            .map(|u| {
                match mode {
                    Mode::Encrypt => {
                        let text = crypter.update(&xor(
                            &pksc7padding(u, self.key.len()),
                            &self.iv
                        ).unwrap());
                        self.set_iv(&text);
                        text
                    },
                    Mode::Decrypt => {
                        let iv = self.iv.clone();
                        self.set_iv(u);
                        xor(
                            &crypter.update(&pksc7padding(u, self.key.len())),
                            &iv
                        ).unwrap()
                    }
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
    data = data.replace("\n", "");
    let data = data.from_base64().unwrap();

    let mut aescbc = AesCBC::new(key.to_vec(), iv.to_vec());
    let plaintext = aescbc.update(Mode::Decrypt, &data);

    aescbc.set_iv(iv);

    assert_eq!(
        aescbc.update(Mode::Encrypt, &plaintext),
        data
    );
}

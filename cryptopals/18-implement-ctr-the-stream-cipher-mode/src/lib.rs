extern crate rustc_serialize;
extern crate openssl;
extern crate fixed_xor;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use openssl::crypto::symm::{ Crypter, Type, Mode };
use fixed_xor::xor;


pub struct AesCTR {
    key: Vec<u8>,
    nonce: Vec<u8>,
    counter: u64
}

impl AesCTR {
    pub fn new(key: &[u8]) -> AesCTR {
        AesCTR::from(key, &rand!(8))
    }
    pub fn from(key: &[u8], nonce: &[u8]) -> AesCTR {
        AesCTR { key: key.into(), nonce: nonce.into(), counter: 0 }
    }
    pub fn set_ctr(mut self, counter: u64) -> AesCTR {
        self.counter = counter;
        self
    }
    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        let crypter = Crypter::new(Type::AES_128_ECB);
        crypter.init(Mode::Encrypt, &self.key, &Vec::new());
        crypter.pad(false);
        data.chunks(self.key.len())
            .map(|u| {
                let counter = self.counter;
                self.counter += 1;
                xor(
                    &crypter.update(&[self.nonce.clone(), store64(counter)].concat())[..u.len()],
                    u
                ).unwrap()
            })
            .collect::<Vec<Vec<u8>>>()
            .concat()
    }
}

pub fn store64(x: u64) -> Vec<u8> {
    println!("{}", x);
    (0..8).map(|i| (x >> 8*i) as u8).collect()
}

#[test]
fn it_works() {
    use rustc_serialize::base64::FromBase64;

    let input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
        .from_base64().unwrap();

    assert_eq!(
        String::from_utf8_lossy(&AesCTR::from(b"YELLOW SUBMARINE", &[0; 8]).update(&input)),
        "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    );

    let input = rand!(rand!(choose 5..45));
    let mut crypter = AesCTR::new(&rand!());
    let output = crypter.update(&input);
    assert_eq!(
        crypter.set_ctr(0).update(&output),
        input
    );
}

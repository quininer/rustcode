extern crate rustc_serialize;
extern crate openssl;
extern crate implement_ctr_the_stream_cipher_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use implement_ctr_the_stream_cipher_mode::{ AesCTR, StreamCipher };


pub trait Edit: StreamCipher {
    fn edit(
        &self,
        ciphertext: &[u8],
        offset: usize,
        newtext: &[u8]
    ) -> Vec<u8>;
}

impl Edit for AesCTR {
    fn edit(
        &self,
        ciphertext: &[u8],
        offset: usize,
        newtext: &[u8]
    ) -> Vec<u8> {
        let mut cipher = self.clone().set_ctr(0);
        let mut plaintext = cipher.update(ciphertext);
        for (i, &n) in newtext.iter().enumerate() {
            plaintext[offset+i] = n;
        }
        cipher.set_ctr(0).update(&plaintext)
    }
}

pub fn crack_ctr_edit(
    ciphertext: &[u8],
    editor: Box<Fn(&[u8], usize, &[u8]) -> Vec<u8>>
) -> Vec<u8> {
    let mut out = vec![0; ciphertext.len()];
    for i in 0..ciphertext.len() {
        'u: for u in 0..std::u8::MAX as usize + 1 {
            out[i] = u as u8;
            if editor(ciphertext, 0, &out)[..i+1] == ciphertext[..i+1] {
                break 'u
            }
        }
    }
    out
}


#[test]
fn it_works() {
    use std::fs::File;
    use std::io::Read;
    use openssl::crypto::symm::{ Crypter, Type, Mode };
    use rustc_serialize::base64::FromBase64;

    let plaintext = {
        let mut input = String::new();
        File::open("examples/25.txt").unwrap()
            .read_to_string(&mut input).unwrap();
        let input = input.from_base64().unwrap();
        let ecb = Crypter::new(Type::AES_128_ECB);
        ecb.init(Mode::Decrypt, b"YELLOW SUBMARINE", &[]);
        [ecb.update(&input), ecb.finalize()].concat()
    };
    let plaintext: Vec<u8> = plaintext[..160].into();
    let mut ctr = AesCTR::new(&rand!());
    let ciphertext = ctr.update(&plaintext);

    assert_eq!(
        plaintext,
        crack_ctr_edit(
            &ciphertext,
            Box::new(move |c, o ,p| ctr.edit(c, o, p))
        )
    );
}

#[test]
fn test_edit() {
    let mut ctr = AesCTR::new(&rand!());
    let ciphertext = ctr.update(b"AAAAAAAAAAAAAAAA");
    assert_eq!(
        ctr.edit(&ciphertext, 6, b"BB"),
        ctr.set_ctr(0).update(b"AAAAAABBAAAAAAAA")
    );
}

extern crate rustc_serialize;
extern crate openssl;

use openssl::crypto::symm::{ Crypter };


pub fn repeating_crypt(crypter: Crypter, data: &[u8], size: usize) -> Vec<u8> {
    data.chunks(size).map(|u| crypter.update(u)).collect::<Vec<Vec<u8>>>().concat()
}


#[test]
fn it_works() {
    use std::fs::File;
    use std::io::Read;
    use openssl::crypto::symm::{ Type, Mode };
    use rustc_serialize::base64::FromBase64;

    let mut data = String::new();
    let key = b"YELLOW SUBMARINE";

    File::open("./examples/7.txt").expect("read error.").read_to_string(&mut data).ok();
    data = data.replace("\n", "");
    let data = data.from_base64().unwrap();

    let encrypter = Crypter::new(Type::AES_128_ECB);
    let decrypter = Crypter::new(Type::AES_128_ECB);
    encrypter.init(Mode::Encrypt, key, &Vec::new());
    decrypter.init(Mode::Decrypt, key, &Vec::new());
    encrypter.pad(false);
    decrypter.pad(false);

    let plaintext = repeating_crypt(decrypter, &data, key.len());

    assert_eq!(data, repeating_crypt(
        encrypter,
        &plaintext,
        key.len()
    ));
}

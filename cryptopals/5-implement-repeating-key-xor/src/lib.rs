extern crate rustc_serialize;
extern crate fixed_xor;

use fixed_xor::{ xor, Error };

pub fn repeating_xor(plain: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();

    for chunk in plain.chunks(key.len()) {
        data.append(&mut try!(xor(
            chunk.to_vec(),
            key[..chunk.len()].to_vec()
        )));
    }

    Ok(data)
}

#[test]
fn it_works() {
    use rustc_serialize::hex::ToHex;

    assert_eq!(
        repeating_xor(
            b"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".to_vec(),
            b"ICE".to_vec()
        ).map(|u| u.to_hex()).ok(),
        Some(String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))
    );
}

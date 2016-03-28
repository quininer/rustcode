extern crate cbc_bitflipping_attacks;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;


pub type Decryptor = Box<Fn(&[u8]) -> Vec<u8>>;

pub fn crack_cbc_recover_iv(cipher: &[u8], decryptor: Decryptor) -> Vec<u8> {
    let out = decryptor(&[
        &cipher[..16],
        &[0; 16],
        &cipher[..16]
    ].concat());
    (0..16).map(|i| out[i] ^ out[i + 32]).collect()
}


#[test]
fn it_works() {
    use cbc_bitflipping_attacks::{ Oracle, Cipher };

    let key = rand!();
    let oracle = Oracle::from(&key, &key);

    let plaintext = b"Take your code from the CBC exercise and modify.";
    let ciphertext = oracle.encrypt(plaintext);

    assert_eq!(
        key,
        crack_cbc_recover_iv(
            &ciphertext,
            Box::new(move |u| oracle.decrypt(u))
        )
    );

    let iv = rand!();
    let oracle = Oracle::new(&iv);
    let ciphertext = oracle.encrypt(plaintext);

    assert_eq!(
        iv,
        crack_cbc_recover_iv(
            &ciphertext,
            Box::new(move |u| oracle.decrypt(u))
        )
    );
}

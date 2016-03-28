extern crate cbc_bitflipping_attacks;
extern crate implement_ctr_the_stream_cipher_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

use std::ops::Range;


pub fn crack_ctr_replace(
    plain: &[u8],
    cipher: &[u8],
    range: Range<usize>,
    text: &[u8]
) -> Vec<u8> {
    assert!(
        cipher.len() >= 32
            && plain.len() >= range.end
            && cipher.len() >= range.end
            && range.end - range.start == text.len()
    );

    [
        cipher[..range.start].into(),
        xor!(
            &cipher[range.clone()],
            &plain[range.clone()],
            text
        ),
        cipher[range.end..].into()
    ].concat()
}


#[test]
fn it_works() {
    use cbc_bitflipping_attacks::{ Cipher, postdata, is_admin };
    use implement_ctr_the_stream_cipher_mode::AesCTR;

    let cipher = AesCTR::new(&rand!());
    let text = postdata([b'x'; 32]);
    let ciphertext = cipher.encrypt(text.as_bytes());

    let cracktext = crack_ctr_replace(
        &text.as_ref(),
        &ciphertext,
        48..64,
        b"xxxxx;admin=true"
    );

    assert!(is_admin(&cipher, &cracktext));
}

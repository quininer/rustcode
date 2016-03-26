extern crate rustc_serialize;
extern crate implement_ctr_the_stream_cipher_mode;
extern crate break_repeating_key_xor;
extern crate break_fixed_nonce_ctr_mode_using_substitions;
#[macro_use] extern crate fixed_xor;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use fixed_xor::xor_by;
use break_repeating_key_xor::zip;


pub fn guess_key(ciphertexts: Vec<Vec<u8>>, tablet: &[u8], more: &[u8]) -> Vec<u8> {
    zip(ciphertexts).iter()
        .map(|r| {
            let out = (0..256)
                .map(|u| u as u8)
                .filter(|&u| !xor_by(r, u).iter()
                    .any(|&n| !tablet.contains(&n))
                )
                .collect::<Vec<u8>>();
            match out.len() {
                0 => panic!("ooh.."),
                1 => out[0],
                _ => out.iter()
                    .cloned()
                    .max_by_key(|&u| xor_by(r, u).iter()
                        .filter(|&n| more.contains(n)).count()
                    )
                    .unwrap()
            }
        })
        .collect()
}


#[test]
fn it_works() {
    use std::fs::File;
    use std::io::Read;
    use rustc_serialize::base64::FromBase64;
    use implement_ctr_the_stream_cipher_mode::{ AesCTR, StreamCipher };
    use break_fixed_nonce_ctr_mode_using_substitions::tailor_stram;

    let mut inputs = String::new();
    File::open("examples/20.txt").unwrap()
        .read_to_string(&mut inputs).unwrap();
    let inputs = inputs.lines()
        .map(|r| r.from_base64().unwrap())
        .collect::<Vec<Vec<u8>>>();

    // let crypter = AesCTR::new(&rand!());
    let crypter = AesCTR::from(&[0; 16], &[0; 8]);
    let ciphertexts = inputs.iter()
        .map(|r| crypter.clone().set_ctr(0).update(r))
        .collect::<Vec<Vec<u8>>>();

    let (minsize, tailortexts) = tailor_stram(&ciphertexts);
    let streamkey = guess_key(
        tailortexts,
        &[
            b" -\\\'\"/!?,.:;".to_vec(),
            (b'a'..b'z'+1).collect(),
            (b'A'..b'Z'+1).collect(),
            (b'0'..b'9'+1).collect()
        ].concat(),
        b" "
    );

    let mut tested = false;

    for (p, c) in inputs.iter()
        .map(|r| r[..minsize].to_vec())
        .zip(ciphertexts.iter())
    {
        tested = true;
        assert_eq!(
            xor!(streamkey.clone(), c.clone()),
            p.clone()
        );
    }

    assert!(tested);
}

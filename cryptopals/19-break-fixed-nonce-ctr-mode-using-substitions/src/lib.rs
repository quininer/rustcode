extern crate rustc_serialize;
extern crate implement_ctr_the_stream_cipher_mode;
extern crate break_repeating_key_xor;
extern crate single_byte_xor_cipher;
#[macro_use] extern crate fixed_xor;
#[macro_use] extern crate an_ebccbc_detection_oracle;


#[test]
fn it_works() {
    use rustc_serialize::base64::FromBase64;
    use implement_ctr_the_stream_cipher_mode::AesCTR;
    use break_repeating_key_xor::guess_key;
    use single_byte_xor_cipher::read_freqsmap;

    let inputs = include_str!("input.txt").lines()
        .map(|r| r.from_base64().unwrap())
        .collect::<Vec<Vec<u8>>>();

    let crypter = AesCTR::new(&rand!());
    let ciphertexts = inputs.iter()
        .map(|r| crypter.clone().set_ctr(0).update(r))
        .collect::<Vec<Vec<u8>>>();

    let minsize = ciphertexts.iter().map(|r| r.len()).min().unwrap();
    let tailortexts = ciphertexts.iter()
        .map(|r| r[..minsize].to_vec())
        .collect::<Vec<Vec<u8>>>();

    let streamkey = guess_key(
        tailortexts.concat(),
        minsize,
        &read_freqsmap("../3-single-byte-xor-cipher/examples/english.txt").ok().unwrap()
    );

    let mut tested = false;

    for (c, p) in ciphertexts.iter()
        .zip(inputs.iter())
        .filter(|&(c, p)| c.len() == minsize && p.len() == minsize)
    {
        tested = true;
        // FIXME FreqsMap without capital letter
        assert_eq!(
            String::from_utf8_lossy(&xor!(streamkey.clone(), c.clone())),
            String::from_utf8_lossy(&p.clone()).to_lowercase()
        );
    }

    assert!(tested);
}

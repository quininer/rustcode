extern crate rustc_serialize;
extern crate implement_ctr_the_stream_cipher_mode;
extern crate break_repeating_key_xor;
extern crate single_byte_xor_cipher;
#[macro_use] extern crate fixed_xor;


pub fn tailor_stram(data: &[Vec<u8>]) -> (usize, Vec<Vec<u8>>) {
    let minsize = data.iter().map(|r| r.len()).min().unwrap();
    (
        minsize,
        data.iter()
            .map(|r| r[..minsize].into())
            .collect()
    )
}

#[test]
fn it_works() {
    use rustc_serialize::base64::FromBase64;
    use implement_ctr_the_stream_cipher_mode::{ AesCTR, StreamCipher };
    use break_repeating_key_xor::guess_key;
    use single_byte_xor_cipher::read_freqsmap;

    let inputs = include_str!("input.txt").lines()
        .map(|r| r.from_base64().unwrap())
        .collect::<Vec<Vec<u8>>>();

    let crypter = AesCTR::from(b"YELLOW SUBMARINE", &[0; 8]);
    let ciphertexts = inputs.iter()
        .map(|r| crypter.clone().set_ctr(0).update(r))
        .collect::<Vec<Vec<u8>>>();

    let (minsize, tailortexts) = tailor_stram(&ciphertexts);
    let streamkey = guess_key(
        tailortexts.concat(),
        minsize,
        &read_freqsmap("../3-single-byte-xor-cipher/examples/english.txt").ok().unwrap()
    );

    let mut tested = false;

    for (p, c) in inputs.iter()
        .map(|r| r[..minsize].to_vec())
        .zip(ciphertexts.iter())
    {
        tested = true;

        // FIXME FreqsMap without capital letter
        assert_eq!(
            String::from_utf8_lossy(&xor!(streamkey.clone(), c.clone())).to_lowercase(),
            String::from_utf8_lossy(&p.clone()).to_lowercase()
        );
    }

    assert!(tested);
}

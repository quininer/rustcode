extern crate rustc_serialize;
extern crate single_byte_xor_cipher;
extern crate detect_single_character_xor;

pub mod hamming;

use single_byte_xor_cipher::FreqsMap;
use detect_single_character_xor::analyse_from_vec;

/// ```
/// use break_repeating_key_xor::zip;
/// assert_eq!(
///     zip(vec![vec![1,2,3], vec![4,5,6], vec![7,8,9]]),
///     vec![vec![1,4,7], vec![2,5,8], vec![3,6,9]]
/// );
/// ```
pub fn zip<T: Clone>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    let mut z = Vec::new();

    for i in 0..v.first().unwrap().len() {
        let mut zz = Vec::new();

        for vv in &v {
            zz.push(vv[i].clone());
        }

        z.push(zz);
    }

    z
}

pub fn guess_key(ciphertext: Vec<u8>, size: usize, fmap: &FreqsMap) -> Vec<u8> {
    analyse_from_vec(
        zip(
            ciphertext
                .chunks(size)
                .filter(|v| v.len() == size)
                .map(|v| v.into())
                .collect()
        ),
        fmap
    ).iter()
        .map(|&(x, _)| x)
        .collect()
}


#[test]
fn it_works() {
    use std::io::Read;
    use std::fs::File;
    use rustc_serialize::base64::FromBase64;
    use single_byte_xor_cipher::read_freqsmap;

    let path = "./examples/6.txt";
    let mut data = String::new();

    File::open(path).expect("read error.").read_to_string(&mut data).ok();
    data = data.replace("\n", "");
    let data = data.from_base64().unwrap();

    let keysize = hamming::guess_keysize(&data, 2..41).ok().unwrap();

    assert_eq!(keysize, 29);

    let key = guess_key(
        data,
        keysize,
        &read_freqsmap("../3-single-byte-xor-cipher/examples/english.txt").ok().unwrap()
    );

    assert_eq!(
        String::from_utf8(key).ok(),
        Some(String::from("Terminator X: Bring the noise"))
    );
}

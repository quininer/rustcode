#![feature(question_mark)]

extern crate pkcs7_padding_validation;
extern crate cbc_bitflipping_attacks;
extern crate implement_pkcs7_padding;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;

use pkcs7_padding_validation::unpksc7padding;
use cbc_bitflipping_attacks::{ Oracle, Cipher };


macro_rules! leftpad {
    ( $data:expr, $len:expr, $default:expr ) => {
        [
            vec![$default; $len - $data.len()],
            $data
        ].concat()
    };
    ( $data:expr, $default:expr ) => {
        leftpad!($data, 16, $default)
    };
    ( $data:expr ) => {
        leftpad!($data, 0)
    }
}

pub type Verifyer = Box<Fn(&[u8], &[u8]) -> bool>;

pub fn is_qualified(oracle: &Oracle, iv: &[u8], data: &[u8]) -> bool {
    let out = oracle.decrypt_with(iv, data);
    unpksc7padding(&out, 16).is_ok()
}

pub fn crack_cbc_block(iv: &[u8], data: &[u8], verify: &Verifyer) -> Result<Vec<u8>, ()> {
    assert_eq!(iv.len(), data.len());
    let mut out = Vec::new();

    for i in 1..iv.len()+1 {
        match (0usize..256)
            .find(|&u| verify(
                &xor!(
                    iv.to_vec(),
                    leftpad!([&[u as u8], &out[..]].concat()),
                    leftpad!(vec![i as u8; i])
                ),
                data
            ) && (!out.is_empty() || verify(
                &xor!(
                    iv.to_vec(),
                    leftpad!(vec![u as u8]),
                    leftpad!(vec![i as u8; 2])
                ),
                data
            )))
        {
            Some(byte) => out.insert(0, byte as u8),
            None => Err(())?
        };
    }

    Ok(out)
}

pub fn crack_cbc_padding(iv: &[u8], data: &[u8], verify: Verifyer) -> Vec<u8> {
    let mut out: Vec<_> = iv.into();
    out.extend_from_slice(&data);
    out.chunks(iv.len())
        .map(|r| r.into())
        .collect::<Vec<Vec<_>>>()
        .windows(2)
        .map(|r| crack_cbc_block(
            r.first().unwrap(),
            r.last().unwrap(),
            &verify
        ).unwrap())
        .collect::<Vec<_>>()
        .concat()
}


#[test]
fn it_works() {
    use implement_pkcs7_padding::pkcs7padding;

    let input = include_str!("input.txt");
    let input: Vec<_> = rand!(choose input.lines()).into();
    let iv = rand!();
    let oracle = Oracle::new(&iv);

    let ciphertext = oracle.encrypt(&pkcs7padding(&input, 16));
    assert!(is_qualified(&oracle, &iv, &ciphertext));

    let output = crack_cbc_padding(
        &iv,
        &ciphertext,
        Box::new(move |iv, u| is_qualified(&oracle, iv, u))
    );
    assert_eq!(
        unpksc7padding(&output, 16).ok().or(Some(output)),
        Some(input)
    );
}

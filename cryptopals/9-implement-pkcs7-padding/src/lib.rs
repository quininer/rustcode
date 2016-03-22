use std::iter;

pub fn pkcs7padding(data: &[u8], len: usize) -> Vec<u8> {
    let pad = len - data.len() % len;
    let mut result = data.to_vec();
    result.append(&mut iter::repeat(pad as u8).take(pad).collect());
    result
}

#[test]
fn it_works() {
    assert_eq!(
        pkcs7padding(b"YELLOW SUBMARINE", 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04"
    );
}

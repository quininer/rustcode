use implement_a_sha_1_keyed_mac::{ Sha1, Digest };


pub fn hmac<H: Digest>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let bs = 64;
    let key = if key.len() > bs {
        H::hash(key)
    } else if key.len() < bs {
        [key, &vec![0; bs-key.len()]].concat()
    } else { key.into() };

    H::hash(&[
        xor!(vec![0x5c; bs], key.clone()),
        H::hash(&[
            &xor!(vec![0x36; bs], key.clone()),
            message
        ].concat())
    ].concat())
}

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<Sha1>(key, message)
}

#[test]
fn test_hmac() {
    use rustc_serialize::hex::ToHex;
    assert_eq!(
        hmac_sha1(b"", b"").to_hex(),
        "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
    );
    assert_eq!(
        hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog").to_hex(),
        "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
    );
}

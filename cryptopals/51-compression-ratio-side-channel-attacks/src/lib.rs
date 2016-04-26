extern crate zlib;
extern crate implement_pkcs7_padding;
extern crate implement_cbc_mode;
extern crate implement_ctr_the_stream_cipher_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use implement_pkcs7_padding::pkcs7padding;
use implement_cbc_mode::{ AesCBC, Mode };
use implement_ctr_the_stream_cipher_mode::{ AesCTR, StreamCipher };
use zlib::{ ZlibProxy, ZlibEvent };


pub static SESSION_ID: &'static str = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=";
pub const PADDING: &'static [u8] = b"!@#$%^&()-`~[]{}*";
pub type CompressionLenOracle = Box<Fn(&[u8], &[u8]) -> usize>;

pub fn compress(data: &[u8]) -> Vec<u8> {
    match ZlibProxy::new().compress(data.into()).recv() {
        Ok(ZlibEvent::CompressCompleted(out)) => out,
        _ => panic!()
    }
}

pub fn uncompress(data: &[u8], size: usize) -> Vec<u8> {
    match ZlibProxy::new().uncompress(data.into(), size).recv() {
        Ok(ZlibEvent::UncompressCompleted(out)) => out,
        _ => panic!()
    }
}

pub fn compression_oracle_with_cbc(p: &[u8]) -> usize {
    AesCBC::new(&rand!(16), &rand!(16)).update(
        Mode::Encrypt,
        &pkcs7padding(&compress(&format_request(p)), 16)
    ).len()
}

pub fn compression_oracle_with_ctr(p: &[u8]) -> usize {
    AesCTR::new(&rand!(16)).update(&compress(&format_request(p))).len()
}

pub fn format_request(p: &[u8]) -> Vec<u8> {
    let header = format!(
"\
POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid={}
Content-Length: {}

",
        SESSION_ID,
        p.len()
    ).into_bytes();
    [header, p.into()].concat()
}

pub fn get_padding(content: &[u8], oracle: &CompressionLenOracle) -> (usize, usize) {
    let base = oracle(content, &[]);
    let padding = (1..17)
        .find(|&u| oracle(content, &PADDING[..u]) > base)
        .unwrap_or(0);
    (oracle(content, &PADDING[..padding]), padding)
}

pub fn guess_compress_secret(prefix: &[u8], tablet: &[u8], oracle: CompressionLenOracle) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let (base, padding) = get_padding(&[prefix, &out, b"*"].concat(), &oracle);
        match tablet.iter()
            .find(|&u| oracle(&[prefix, &out, &[*u]].concat(), &PADDING[..padding]) < base)
        {
            Some(&u) => out.push(u),
            None => break
        }
    }
    out
}


#[test]
fn it_works() {
    let guess_secret = guess_compress_secret(
        b"Cookie: sessionid=",
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/=",
        Box::new(|u, _| compression_oracle_with_ctr(&[u; 8].concat()))
    );
    assert_eq!(guess_secret, SESSION_ID.as_bytes());

    let guess_secret = guess_compress_secret(
        b"Cookie: sessionid=",
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/=",
        Box::new(|u, p| compression_oracle_with_cbc(&[
            vec![u; 8].concat(),
            p.into()
        ].concat()))
    );
    assert_eq!(guess_secret, SESSION_ID.as_bytes());

    let guess_host = guess_compress_secret(
        b"Host: ",
        b"abcdefghijklmnopqrstuvwxyz1234567890@%&=:./?",
        Box::new(|u, _| compression_oracle_with_ctr(&[u; 8].concat()))
    );
    assert_eq!(guess_host, b"hapless.com");
}

#[test]
fn test_zlib() {
    let data = [rand!(50), vec![0; 50], rand!(50)].concat();
    let compressed_data = compress(&data);
    assert!(compressed_data.len() < data.len());
    assert_eq!(uncompress(&compressed_data, data.len()), data);

    assert!(
        compress(&format_request(&vec!["Cookie: sessionid=T".as_bytes(); 8].concat())).len()
        <
        compress(&format_request(&vec!["Cookie: sessionid=X".as_bytes(); 8].concat())).len()
    );
}

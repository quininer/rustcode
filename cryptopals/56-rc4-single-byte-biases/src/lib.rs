extern crate rustc_serialize;
extern crate implement_ctr_the_stream_cipher_mode;
#[macro_use] extern crate an_ebccbc_detection_oracle;

mod rc4;

pub use rc4::RC4;


pub const FULL_WEIGHT: usize = 4;
pub const HALF_WEIGHT: usize = 1;
pub type Rc4Oracle = Box<Fn(&[u8]) -> Vec<u8>>;

pub fn winner(byte: &[usize]) -> u8 {
    assert_eq!(byte.len(), 256);
    (0..byte.len())
        .max_by_key(|&i| byte[i])
        .unwrap() as u8
}

pub fn recover_rc4_cookie(counts: &[Vec<usize>]) -> Vec<u8> {
    counts.iter()
        .map(|bs| winner(bs))
        .collect()
}

pub fn crack_rc4_cookie(oracle: Rc4Oracle) -> Vec<u8> {
    use std::io::{ Write, stderr };
    let mut log = stderr();

    let cookie_len = oracle(&[]).len();
    assert_eq!(cookie_len, 30);
    let mut counts: Vec<Vec<usize>> = (0..cookie_len).map(|_| vec![0; 256]).collect();
    let mut prefix = vec![0; 2];

    while prefix.len() < 18 {
        let pl = prefix.len();
        for _ in 0..2usize.pow(24) {
            let ciphertext = oracle(&prefix);

            if prefix.len() <= 15 {
                let b16 = ciphertext[15] as usize;
                counts[15 - pl][b16 ^ 240] += FULL_WEIGHT;
                counts[15 - pl][b16 ^ 0] += HALF_WEIGHT;
                counts[15 - pl][b16 ^ 16] += HALF_WEIGHT;
            }

            let b32 = ciphertext[31] as usize;
            counts[31 - pl][b32 ^ 224] += FULL_WEIGHT;
            counts[31 - pl][b32 ^ 0] += HALF_WEIGHT;
            counts[31 - pl][b32 ^ 32] += HALF_WEIGHT;
        }

        log.write_fmt(format_args!(
            "{}\n",
            to_visible(&recover_rc4_cookie(&counts))
        )).ok();
        prefix.push(0x00);
    }

    recover_rc4_cookie(&counts)
}

pub fn to_visible(data: &[u8]) -> String {
    let out = data.iter()
        .map(|&r| if is_visible(r) { r } else { b'.' })
        .collect();
    String::from_utf8(out).unwrap()
}

#[inline]
fn is_visible(r: u8) -> bool {
    (31 < r as u8) && (127 > r as u8)
}


#[test]
fn it_works() {
    use rustc_serialize::base64::FromBase64;
    use implement_ctr_the_stream_cipher_mode::StreamCipher;

    let secret = "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F".from_base64().unwrap();

    assert_eq!(
        secret.clone(),
        crack_rc4_cookie(Box::new(move |u|
            RC4::new(&rand!(16)).update(&[u, &secret].concat())
        ))
    );
}

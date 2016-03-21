extern crate rand;
extern crate openssl;
extern crate detect_aes_in_ecb_mode;

pub use rand::{ random, sample, thread_rng, Rng };
use openssl::crypto::symm::{ Crypter, Type, Mode };


#[macro_export]
macro_rules! rand {
    ( $len:expr ) => {{
        use $crate::Rng;
        $crate::thread_rng().gen_iter().take($len).collect::<Vec<u8>>()
    }};
    ( choose $range:expr ) => {
        $crate::sample(&mut $crate::thread_rng(), $range, 1)[0]
    };
    () => { rand!(16) }
}

pub fn encryption_oracle(data: Vec<u8>) -> (bool, Vec<u8>) {
    let data = [
        rand!(rand!(choose 5..10)),
        data,
        rand!(rand!(choose 5..10))
    ].concat();

    let key = rand!();

    let (x, c) = if random() {
        let ecb = Crypter::new(Type::AES_128_ECB);
        ecb.init(Mode::Encrypt, &key, &[]);
        ecb.pad(true);
        (true, ecb)
    } else {
        let iv = rand!();
        let cbc = Crypter::new(Type::AES_128_CBC);
        cbc.init(Mode::Encrypt, &key, &iv);
        cbc.pad(true);
        (false, cbc)
    };

    (x, c.update(&data))
}


#[test]
fn it_works() {
    use detect_aes_in_ecb_mode::repetition_rate;

    let total = 64;
    let mut count = 0;

    for _ in 0..total {
        let (r, data) = encryption_oracle(vec![random(); rand!(choose 32..96)]);
        if (repetition_rate(&data, 16) > 0.3) == r {
            count += 1;
        }
    }

    assert!(count as f64 / total as f64 > 0.7);
}

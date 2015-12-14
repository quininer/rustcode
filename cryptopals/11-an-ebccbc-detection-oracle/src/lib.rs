extern crate rand;
extern crate openssl;
extern crate detect_aes_in_ecb_mode;

use rand::{ random, sample, thread_rng, Rng };
use openssl::crypto::symm::{ Crypter, Type, Mode };

pub fn encryption_oracle(data: Vec<u8>) -> (bool, (Vec<u8>, Vec<u8>)) {
    let prefix = thread_rng().gen_iter::<u8>()
        .take(sample(&mut thread_rng(), 5..10, 1)[0]).collect::<Vec<u8>>();
    let suffix = thread_rng().gen_iter::<u8>()
        .take(sample(&mut thread_rng(), 5..10, 1)[0]).collect::<Vec<u8>>();

    let data = [prefix, data, suffix].concat();

    let key = thread_rng().gen_iter::<u8>().take(16).collect::<Vec<u8>>();
    let iv = thread_rng().gen_iter::<u8>().take(16).collect::<Vec<u8>>();

    let ebc = Crypter::new(Type::AES_128_ECB);
    let cbc = Crypter::new(Type::AES_128_CBC);
    ebc.init(Mode::Encrypt, &key, &[]);
    cbc.init(Mode::Encrypt, &key, &iv);

    let (one, two) = data.split_at(data.len() / 2);
    let (x, (x1, x2)) = if random() {
        (true, (ebc, cbc))
    } else {
        (false, (cbc, ebc))
    };

    (x, (x1.update(one), x2.update(two)))
}

#[test]
fn it_works() {
    use detect_aes_in_ecb_mode::repetition_rate;

    let total = 64;
    let mut count = 0;

    for _ in 0..total {
        let (r, (data1, data2)) = encryption_oracle(vec![random::<u8>(); 96]);
        if (repetition_rate(data1, 16) > repetition_rate(data2, 16)) == r {
            count += 1;
        };
    }

    assert!(count as f64 / total as f64 >= 0.5);
}

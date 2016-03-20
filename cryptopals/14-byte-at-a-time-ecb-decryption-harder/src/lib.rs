extern crate rand;
extern crate rustc_serialize;
extern crate byte_at_a_time_ecb_decryption_simple;
#[macro_use] extern crate an_ebccbc_detection_oracle;

#[test]
fn it_works() {
    use rand::{ thread_rng, sample, Rng };
    use rustc_serialize::base64::FromBase64;
    use byte_at_a_time_ecb_decryption_simple::{
        Oracle,
        crack_blocksize,
        crack_plaintext
    };

    let data = include_str!("input.txt");
    let data = data.from_base64().unwrap();
    let prefix = rand!(rand!(choose 0..std::u8::MAX as usize));
    let oracle = Oracle::new(&prefix, &data);

    let empty_bs = oracle.encryption(&[]).len();
    let (bs, i) = crack_blocksize(&oracle);
    assert_eq!(empty_bs, prefix.len() + data.len() + i);

    // FIXME should not have data info.
    // diff encrypt([]) and encrypt([..])
    // guess data len.
    let offset = empty_bs - data.len() - i;
    let i = bs - offset % bs;
    let offset = offset + i;

    assert_eq!(
        crack_plaintext((offset, i), bs, &oracle),
        data
    );
}

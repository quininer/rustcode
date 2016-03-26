extern crate implement_the_mt19937_mersenne_twister_rng;
extern crate time;
#[macro_use] extern crate an_ebccbc_detection_oracle;


#[test]
fn it_works() {
    use implement_the_mt19937_mersenne_twister_rng::MT19937;
    use time::get_time;

    let timestamp = get_time().sec + rand!(choose 40..1000);
    let mut mt_rng = MT19937::new(timestamp as u32);
    let out = mt_rng.u32();

    let mut guess_ts = get_time().sec + 1500;
    loop {
        if MT19937::new(guess_ts as u32).u32() == out {
            break
        }
        guess_ts -= 1;
    }

    assert_eq!(timestamp, guess_ts);
}

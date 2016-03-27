extern crate implement_the_mt19937_mersenne_twister_rng;
extern crate time;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use std::ops::Range;
use implement_the_mt19937_mersenne_twister_rng::MT19937;


pub fn crack_mt19937_seed(range: Range<u32>, out: &[usize]) -> Result<u32, ()> {
    range.clone().find(|&seed| MT19937::new(seed)
        .take(out.len())
        .collect::<Vec<_>>() == out.to_vec()
    ).ok_or(())
}


#[test]
fn it_works() {
    use time::get_time;

    let timestamp = get_time().sec as u32 + rand!(choose 40..1000);
    let mt_rng = MT19937::new(timestamp);
    let out = mt_rng.take(10).collect::<Vec<_>>();
    let now = get_time().sec as u32;

    assert_eq!(
        crack_mt19937_seed(now-1500..now+1500, &out).ok(),
        Some(timestamp)
    );
}

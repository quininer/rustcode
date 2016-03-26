extern crate implement_the_mt19937_mersenne_twister_rng;
extern crate time;


pub fn untemper(mut y: u32) -> u32 {
    y ^= y >> 18;
    y ^= (y << 15) & 0xEFC60000;
    y ^= ((y << 7) & 0x9D2C5680)
        ^ ((y << 14) & 0x94284000)
        ^ ((y << 21) & 0x14200000)
        ^ ((y << 28) & 0x10000000);
    y ^= (y >> 11) ^ (y >> 22);
    y
}


#[test]
fn it_works() {
    use time::get_time;
    use implement_the_mt19937_mersenne_twister_rng::MT19937;

    let mut mt_rng = MT19937::new(get_time().sec as u32);
    let mut mt_state = [0; 624];
    for i in 0..624 {
        mt_state[i] = untemper(mt_rng.u32());
    }

    let mut mt_rng_replica = MT19937::from(&mt_state, 0);

    assert_eq!(mt_rng.u32(), mt_rng_replica.u32());
    assert_eq!(
        mt_rng.take(1024).collect::<Vec<_>>(),
        mt_rng_replica.take(1024).collect::<Vec<_>>()
    );
}

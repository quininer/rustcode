extern crate implement_and_break_hmac_sha1_with_an_artificial_timing_leak;
extern crate rouille;

#[test]
fn it_works() {
    use std::thread::spawn;
    use rouille::start_server;
    use implement_and_break_hmac_sha1_with_an_artificial_timing_leak::{
        hmac_app, crack_hmac_app, INTERVAL, check
    };

    unsafe { INTERVAL = 5 };
    spawn(|| start_server("127.0.0.1:8000", hmac_app));

    let crack_file = b"bad";
    let crack_hash = crack_hmac_app(
        20,
        5,
        Box::new(move |u| check(crack_file, u))
    );

    assert!(check(crack_file, &crack_hash));
}

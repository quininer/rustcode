#[allow(dead_code)]
fn gcd(mut x: isize, mut y: isize) -> isize {
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }

    x
}

#[test]
fn it_works() {
    assert_eq!(gcd(12, 8), 4);
    assert_eq!(gcd(252, 105), 21);
}

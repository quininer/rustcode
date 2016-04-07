pub fn gcd(mut x: usize, mut y: usize) -> usize {
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

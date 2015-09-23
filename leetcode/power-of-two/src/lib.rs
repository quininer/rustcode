#[allow(dead_code)]
fn is_pot(num: usize) -> bool {
    if num == 1 {
        true
    } else if num % 2 == 0 && num != 0 {
        is_pot(num / 2)
    } else {
        false
    }
}

#[test]
fn it_works() {
    assert!(is_pot(4));
    assert!(is_pot(2048));
    assert!(!is_pot(0));
    assert!(!is_pot(9));
}

#[allow(dead_code)]
fn is_ugly(mut num: i32) -> bool {
    let mut uglys = vec![2, 3, 5];

    while !uglys.is_empty() {
        for u in 0..uglys.len() {
            if num == 1 {
                return true;
            };

            if num % uglys[u] == 0 {
                num /= uglys[u];
            } else {
                uglys.remove(u);
                break;
            };
        };
    };

    false
}

#[test]
fn it_works() {
    assert!(is_ugly(6));
    assert!(is_ugly(8));
    assert!(!is_ugly(14));
}

#[allow(dead_code)]
fn add_digits(num: usize) -> usize {
    let n = format!("{}", num);
    if n.len() == 1 {
        n.parse().unwrap()
    } else {
        add_digits(
            n.split("")
                .filter(|s| s.len() == 1)
                .map(|s| s.parse::<usize>().unwrap())
                .fold(0, |sum, i| sum + i)
        )
    }
}

#[test]
fn it_works() {
    assert_eq!(add_digits(38), 2);
}

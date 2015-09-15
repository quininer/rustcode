#[allow(dead_code)]

fn summary(list: Vec<usize>) -> Vec<String> {
    let mut l = list.clone();
    let mut result = vec![];
    let mut left = String::new();
    l.push(!0);

    for (n, x) in l.iter().zip(&l[1..l.len()]) {
        if left.len() == 0 {
            left = format!("{}", n);
        }
        if n+1 != *x {
            result.push(
                if left.parse::<usize>().unwrap() == *n {
                    format!("{}", left)
                } else {
                    format!("{}->{}", left, n)
                }
            );
            left = format!("{}", x);
        };
    };

    result
}

#[test]
fn it_works() {
    assert_eq!(summary(vec![0, 1, 2, 4, 5, 7]), vec!["0->2", "4->5", "7"]);
}

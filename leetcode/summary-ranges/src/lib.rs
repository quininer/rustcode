#[allow(dead_code)]

fn summary(list: Vec<usize>) -> Vec<String> {
    let mut l = list.clone();
    let mut result = vec![];
    let mut left = String::new();
    l.push(!0);

    for w in l.windows(2) {
        if left.len() == 0 {
            left = format!("{}", w[0]);
        }
        if w[0]+1 != w[1] {
            result.push(
                if left.parse::<usize>().unwrap() == w[0] {
                    format!("{}", left)
                } else {
                    format!("{}->{}", left, w[0])
                }
            );
            left = format!("{}", w[1]);
        };
    };

    result
}

#[test]
fn it_works() {
    assert_eq!(summary(vec![0, 1, 2, 4, 5, 7]), vec!["0->2", "4->5", "7"]);
}

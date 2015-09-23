#[allow(dead_code)]
fn movez(nums: Vec<usize>) -> Vec<usize> {
    let mut zeroes = Vec::new();

    let mut result: Vec<usize> = nums.iter().filter(|&n| {
        if n == &0 {
            zeroes.push(*n);
            false
        } else {
            true
        }
    }).cloned().collect();

    result.append(&mut zeroes);
    result
}

#[test]
fn it_works() {
    assert_eq!(movez(vec![0, 1, 0, 3, 12]), vec![1, 3, 12, 0, 0]);
}

#[allow(dead_code)]
fn contains_duplicate(nums: Vec<usize>) -> bool {
    let mut nums_less = nums.clone();
    nums_less.dedup();
    nums.len() > nums_less.len()
}

#[test]
fn it_works() {
    assert!(!contains_duplicate(vec![1, 2, 3, 4, 5]));
    assert!(contains_duplicate(vec![1, 2, 2, 4, 5]));
}

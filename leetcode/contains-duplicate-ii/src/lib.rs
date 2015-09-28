use std::collections::HashMap;

#[allow(dead_code)]
fn contains_nearby_duplicate(nums: Vec<usize>, k: usize) -> bool {
    let mut map: HashMap<usize, usize> = HashMap::new();
    for i in 0..nums.len() {
        if let Some(n) = map.clone().get(&nums[i]) {
            if i - n < k {
                return true;
            };
        } else {
            map.insert(nums[i], i);
        };
    };

    false
}

#[test]
fn it_works() {
    assert!(!contains_nearby_duplicate(vec![1, 2, 3, 4, 5], 3));
    assert!(contains_nearby_duplicate(vec![1, 2, 3, 2, 5], 3));
    assert!(!contains_nearby_duplicate(vec![1, 2, 3, 4, 1], 3));
}

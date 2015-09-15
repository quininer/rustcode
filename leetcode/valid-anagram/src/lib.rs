#[allow(dead_code)]
fn is_anagram(s: &str, t: &str) -> bool {
    if s == t || s.len() != t.len() {
        return false;
    };

    for b in s.chars() {
        if t.find(b).is_none() {
            return false;
        };
    };

    for b in t.chars() {
        if s.find(b).is_none() {
            return false;
        };
    };

    true
}

#[test]
fn it_works() {
    assert!(is_anagram("anagram", "nagaram"));
    assert!(!is_anagram("rat", "cat"));
}

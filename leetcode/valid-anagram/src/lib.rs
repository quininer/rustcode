#[allow(dead_code)]
fn is_anagram(s: &str, t: &str) -> bool {
    if s == t || s.len() != t.len() {
        return false;
    };

    let mut sv = s.chars().rev().collect::<Vec<char>>();
    let mut tv = t.chars().rev().collect::<Vec<char>>();
    sv.sort();
    tv.sort();
    sv == tv
}

#[test]
fn it_works() {
    assert!(is_anagram("anagram", "nagaram"));
    assert!(!is_anagram("rat", "cat"));
    assert!(!is_anagram("abb", "baa"));
}

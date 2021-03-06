#![feature(negate_unsigned)]

#[allow(dead_code)]
fn str_find(haystack: &str, needle: &str) -> isize {
    // haystack.find(needle).unwrap_or(-1)
    if haystack.len() == 0 || needle.len() == 0 {
        return -1;
    };

    let s = needle.as_bytes()[0];
    let mut j = 0;

    for b in haystack.bytes() {
        if haystack.len() - j < needle.len() {
            break;
        };
        if b == s && &haystack[j..j+needle.len()] == needle {
            return j as isize;
        };

        j += 1;
    };

    -1
}

#[test]
fn it_works() {
    assert_eq!(str_find("Implement strStr().", "strStr"), 10);
    assert_eq!(str_find("Returns the index of the first occurrence of needle in haystack", "e"), 1);
    assert_eq!(str_find(", or -1 if needle is not part of haystack.", "strStr"), -1);
    assert_eq!(str_find("leetcode", ""), -1);
    assert_eq!(str_find("leetcode", "leetcodeleetcode"), -1);
}

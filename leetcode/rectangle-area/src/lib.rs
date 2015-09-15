use std::cmp::{max, min};

#[allow(dead_code)]
fn compute_area(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, h: i64) -> i64 {
    (c - a) * (d - b) + (g - e) * (h - f) - (min(g, c) - max(a, e)) * (min(h, d) - max(f, b))
}

#[test]
fn it_works() {
    assert_eq!(compute_area(-3, 0, 3, 4, 0, -1, 9, 2), 45);
}

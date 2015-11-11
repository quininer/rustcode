#[no_mangle]
pub extern fn foo(bar: isize) -> isize {
    bar.pow(bar as u32)
}

#[test]
fn it_works() {
    assert_eq!(foo(4), 256);
}

#[no_mangle]
pub unsafe fn foo(bar: isize) -> isize {
    bar.pow(bar as u32)
}

#[test]
fn it_works() {
    assert_eq!(unsafe { foo(4) }, 256);
}

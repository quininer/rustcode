#![no_std]

#[allow(non_camel_case_types)]
type c_char = i8;

extern {
    fn printk(data: *const c_char);
}


#[no_mangle]
pub unsafe extern fn init_mod() -> i32 {
    printk(b"rkm: Hello World.\n\0".as_ptr() as *const c_char);
    0
}

#[no_mangle]
pub unsafe extern fn exit_mod() {
    printk(b"rkm: Goodbye World.\n\0".as_ptr() as *const c_char);
}

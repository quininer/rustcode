extern crate libc;
extern crate libloading;

use libc::{ c_char, FILE };
use libloading::{ Library, Symbol };


#[no_mangle]
pub unsafe extern fn fopen(filename: *const c_char, mode: *const c_char) -> *mut FILE {
    println!("Hook!");

    let lib = Library::new("/usr/lib/libc.so.6").unwrap();
    let sym: Symbol<fn(*const c_char, *const c_char) -> *mut FILE> =
        lib.get(b"fopen\0").unwrap();

    sym(filename, mode)
}

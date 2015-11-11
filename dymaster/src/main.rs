extern crate libloading;

use std::env::{ args };
use libloading::{ Library, Symbol };

fn main() {
    let slave = Library::new(
        args().nth(1).unwrap_or("libslave.so".to_string())
    ).expect("Load the library error.");

    let foo: Symbol<extern fn(isize) -> isize> = unsafe {
        slave.get(b"foo\0").expect("slave library not foo function!")
    };

    println!("{}", foo(
        args()
            .nth(2).unwrap_or(String::from("4"))
            .parse().unwrap_or(4)
    ));
}

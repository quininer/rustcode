extern crate libloading;

use std::env::{ args };
use libloading::{ Library, Symbol };


fn main() {
    let slave = Library::new(&args().nth(1).unwrap())
        .expect("load the library error.");

    let foo: Symbol<fn(usize) -> usize> = unsafe {
        slave.get(b"foo\0").expect("not found foo function.")
    };

    println!("{}", foo(
        args()
            .nth(2).unwrap_or(String::from("4"))
            .parse().expect("need a number.")
    ));
}

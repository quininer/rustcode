use std::fs::File;
use std::io::Read;
use std::env::args;

fn main() {
    let mut output = String::new();
    File::open(args().nth(1).unwrap()).unwrap()
        .read_to_string(&mut output).unwrap();
    println!("{}", output);
}

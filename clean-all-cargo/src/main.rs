extern crate walkdir;

use std::env::args;
use std::io;
use std::process::Command;
use walkdir::WalkDir;


#[inline]
fn start(dir: &str) -> io::Result<()> {
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().join("Cargo.lock").is_file())
    {
        println!("clean: {}", entry.path().to_string_lossy());
        Command::new("cargo")
            .current_dir(entry.path())
            .arg("clean")
            .output()?;
    }

    Ok(())
}

fn main() {
    let dir = args().nth(1).unwrap_or(String::from("."));
    start(&dir).unwrap();
}

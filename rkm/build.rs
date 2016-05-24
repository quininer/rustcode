use std::fs::File;
use std::io::Write;

const NAME: &'static str = env!("CARGO_PKG_NAME");
const KOC_TPL: &'static str = include_str!("koc.tpl");

fn main() {
    let koc = KOC_TPL.replace("{ko}", NAME);

    File::create(format!("{}-build.c", NAME)).unwrap()
        .write(koc.as_bytes()).unwrap();
}

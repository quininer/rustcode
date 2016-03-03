extern crate rustc_serialize;
extern crate itertools;

use itertools::Itertools;


pub fn repetition_rate(data: &[u8], size: usize) -> f64 {
    let mut total = 0;
    let mut count = 0;

    for (x, y) in data.chunks(size).combinations() {
        for (n, m) in x.iter().zip(y.iter()) {
            total += 1;
            if n == m {
                count += 1;
            }
        }
    }

    count as f64 / total as f64
}


#[test]
fn it_works() {
    use std::fs::File;
    use std::io::Read;
    use rustc_serialize::hex::FromHex;
    use rustc_serialize::hex::ToHex;

    let mut data = String::new();
    let path = "./examples/8.txt";
    let keysize = 16;

    File::open(path).expect("read error.").read_to_string(&mut data).ok();
    let mut datas = data.lines()
        .map(|s| s.from_hex().ok().unwrap())
        .map(|s| (s.clone(), repetition_rate(&s, keysize)))
        .collect::<Vec<(Vec<u8>, f64)>>();

    datas.sort_by(|&(_, n), &(_, m)| m.partial_cmp(&n).unwrap());

    let (target, _) = datas.first().unwrap().clone();

    assert_eq!(
        target.to_hex(),
        "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    );
}

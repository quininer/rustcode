use std::io;
use std::hash::Hasher;
use byteorder::{ LittleEndian, WriteBytesExt, ReadBytesExt };
use implement_a_sha_1_keyed_mac::{ padding, Digest };


pub struct MD4(u32, u32, u32, u32);

impl Default for MD4 {
    fn default() -> MD4 {
        MD4(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    }
}

impl MD4 {
    pub fn new() -> MD4 {
        MD4::default()
    }

    pub fn from(mut hash: &[u8]) -> io::Result<MD4> {
        Ok(MD4(
            hash.read_u32::<LittleEndian>()?,
            hash.read_u32::<LittleEndian>()?,
            hash.read_u32::<LittleEndian>()?,
            hash.read_u32::<LittleEndian>()?
        ))
    }

    pub fn process(&mut self, mut block: &[u8]) {
        assert_eq!(block.len(), 64);
        println!("{:?}", block);

        let mut data = Vec::new();
        loop {
            data.push(match block.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break
            });
        }

        let &mut MD4(mut a, mut b, mut c, mut d) = self;

        for &i in &[0, 4, 8, 12] {
            a = round_1(a, b, c, d, data[i], 3);
            d = round_1(d, a, b, c, data[i+1], 7);
            c = round_1(c, d, a, b, data[i+2], 11);
            b = round_1(b, c, d, a, data[i+3], 19);
        }
        for i in 0..4 {
            a = round_2(a, b, c, d, data[i], 3);
            d = round_2(d, a, b, c, data[i+4], 5);
            c = round_2(c, d, a, b, data[i+8], 9);
            b = round_2(b, c, d, a, data[i+12], 13);
        }
        for &i in &[0, 2, 1, 3] {
            a = round_3(a, b, c, d, data[i], 3);
            d = round_3(d, a, b, c, data[i+8], 9);
            c = round_3(c, d, a, b, data[i+4], 11);
            b = round_3(b, c, d, a, data[i+12], 15);
        }

        self.0 = self.0.wrapping_add(a);
        self.1 = self.1.wrapping_add(b);
        self.2 = self.2.wrapping_add(c);
        self.3 = self.3.wrapping_add(d);
    }

    fn input(&mut self, data: &[u8]) {
        let data = padding::<LittleEndian>(data, 0).unwrap();
        for u in data.chunks(64) {
            self.process(u);
        }
    }

    fn output(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        out.write_u32::<LittleEndian>(self.0)?;
        out.write_u32::<LittleEndian>(self.1)?;
        out.write_u32::<LittleEndian>(self.2)?;
        out.write_u32::<LittleEndian>(self.3)?;
        Ok(out)
    }
}

impl Hasher for MD4 {
    fn write(&mut self, bytes: &[u8]) {
        self.input(bytes)
    }
    fn finish(&self) -> u64 {
        0
    }
}

impl Digest for MD4 {
    fn bs() -> usize { 64 }
    fn digest(&mut self) -> Vec<u8> {
        self.output().unwrap()
    }
    fn hash(bytes: &[u8]) -> Vec<u8> {
        let mut hasher = MD4::new();
        hasher.write(bytes);
        hasher.digest()
    }
}

fn round_1(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    a
        .wrapping_add((b & c) | (!b & d))
        .wrapping_add(x)
        .rotate_left(s)
}

fn round_2(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    a
        .wrapping_add((b & c) | (b & d) | (c & d))
        .wrapping_add(x)
        .wrapping_add(0x5a827999)
        .rotate_left(s)
}

fn round_3(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    a
        .wrapping_add(b ^ c ^ d)
        .wrapping_add(x)
        .wrapping_add(0x6ED9EBA1)
        .rotate_left(s)
}


#[test]
fn test_md4() {
    use rustc_serialize::hex::FromHex;

    assert_eq!(
        MD4::hash(b""),
        "31d6cfe0d16ae931b73c59d7e0c089c0".from_hex().unwrap()
    );
    assert_eq!(
        MD4::hash(b"The quick brown fox jumps over the lazy dog"),
        "1bee69a46ba811185c194762abaeae90".from_hex().unwrap()
    );
    assert_eq!(
        MD4::hash(b"The quick brown fox jumps over the lazy cog"),
        "b86e130ce7028da59e672d56ad0113df".from_hex().unwrap()
    );
}

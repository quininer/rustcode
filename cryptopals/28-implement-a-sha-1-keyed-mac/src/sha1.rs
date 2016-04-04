use std::hash::Hasher;
use std::io::{ self, Write };
use byteorder::{ BigEndian, WriteBytesExt, ReadBytesExt, ByteOrder };


const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;


#[derive(Clone, Debug)]
pub struct Sha1(u32, u32, u32, u32, u32);

impl Default for Sha1 {
    fn default() -> Sha1 {
        Sha1(H0, H1, H2, H3, H4)
    }
}

impl Sha1 {
    pub fn new() -> Sha1 {
        Sha1::default()
    }

    pub fn from(mut hash: &[u8]) -> io::Result<Sha1> {
        Ok(Sha1(
            hash.read_u32::<BigEndian>()?,
            hash.read_u32::<BigEndian>()?,
            hash.read_u32::<BigEndian>()?,
            hash.read_u32::<BigEndian>()?,
            hash.read_u32::<BigEndian>()?
        ))
    }

    pub fn process(&mut self, block: &[u8]) {
        assert_eq!(block.len(), 64);

        let mut words = [0; 80];
        for (i, n) in block.chunks(4)
            .map(|mut u| u.read_u32::<BigEndian>().unwrap())
            .enumerate()
        {
            words[i] = n;
        }

        for i in 16..80 {
            words[i] = (
                words[i-3]
                    ^ words[i-8]
                    ^ words[i-14]
                    ^ words[i-16]
            ).rotate_left(1);
        }

        let &mut Sha1(mut a, mut b, mut c, mut d, mut e) = self;
        for (i, &n) in words.iter().enumerate() {
            let (k, f) = match i {
                0...19 => (0x5A827999, (b & c) | (!b & d)),
                20...39 => (0x6ED9EBA1, b ^ c ^ d),
                40...59 => (0x8F1BBCDC, (b & c) | (b & d) | (c & d)),
                60...79 => (0xCA62C1D6, b ^ c ^ d),
                _ => unreachable!()
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(n);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.0 = self.0.wrapping_add(a);
        self.1 = self.1.wrapping_add(b);
        self.2 = self.2.wrapping_add(c);
        self.3 = self.3.wrapping_add(d);
        self.4 = self.4.wrapping_add(e);
    }

    fn input(&mut self, data: &[u8]) {
        let data = padding::<BigEndian>(data, 0).unwrap();
        for u in data.chunks(64) {
            self.process(u);
        }
    }

    fn output(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        out.write_u32::<BigEndian>(self.0)?;
        out.write_u32::<BigEndian>(self.1)?;
        out.write_u32::<BigEndian>(self.2)?;
        out.write_u32::<BigEndian>(self.3)?;
        out.write_u32::<BigEndian>(self.4)?;
        Ok(out)
    }
}

pub trait Digest: Hasher {
    fn bs() -> usize;
    fn digest(&mut self) -> Vec<u8>;
    fn hash(bytes: &[u8]) -> Vec<u8>;
}

impl Digest for Sha1 {
    fn bs() -> usize { 64 }
    fn digest(&mut self) -> Vec<u8> {
        self.output().unwrap()
    }
    fn hash(bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.write(bytes);
        hasher.digest()
    }
}

impl Hasher for Sha1 {
    fn write(&mut self, bytes: &[u8]) {
        self.input(bytes)
    }
    fn finish(&self) -> u64 {
        0
    }
}

pub fn padding<E: ByteOrder>(data: &[u8], offset: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.write(data)?;
    out.write_u8(0x80)?;

    if out.len() % (512 / 8) == (448 / 8) {
        out.write_u8(0)?;
    }

    while out.len() % (512 / 8) != (448 / 8) {
        out.write_u8(0)?;
    }

    out.write_u64::<E>((data.len() + offset) as u64 * 8)?;
    Ok(out)
}

#[test]
fn test_padding() {
    let data = b"implement-a-sha-1-keyed-mac";
    let out = padding::<BigEndian>(data, 0).unwrap();
    assert_eq!(
        out.len() % 64,
        0
    );
    assert_eq!(
        &out[..out[out.len()-1] as usize / 8],
        data
    );
}

extern crate implement_ctr_the_stream_cipher_mode;

use std::num::Wrapping;
use implement_ctr_the_stream_cipher_mode::StreamCipher;


pub struct MT19937 {
    mt: [u32; 624],
    index: usize
}

impl MT19937 {
    pub fn new(seed: u32) -> MT19937 {
        let mut rng = MT19937 {
            mt: [0; 624],
            index: 0
        };
        rng.mt[0] = seed;
        for i in 1..624 {
            rng.mt[i] = (
                Wrapping(1812433253)
                * Wrapping(rng.mt[i-1] ^ (rng.mt[i-1] >> 30))
                + Wrapping(i as u32)
            ).0;
        }
        rng
    }

    pub fn from(state: &[u32; 624], index: usize) -> MT19937 {
        MT19937 { mt: *state, index: index }
    }

    fn gen(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) + (self.mt[(i+1) % 264] & 0x7fffffff);
            self.mt[i] = self.mt[(i+397) % 624] ^ (y >> 1);
            if (y % 2) != 0 {
                self.mt[i] = self.mt[i] ^ 2567483615;
            }
        }
    }

    pub fn u32(&mut self) -> u32 {
        if self.index == 0 {
            self.gen();
        }

        let y = temper(self.mt[self.index]);
        self.index = (self.index + 1) % self.mt.len();
        y
    }
}

pub fn temper(mut y: u32) -> u32 {
    y ^= y >> 11;
    y ^= (y << 7) & 2636928640;
    y ^= (y << 15) & 4022730752;
    y ^= y >> 18;
    y
}

impl Iterator for MT19937 {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.u32() as usize)
    }
}

impl StreamCipher for MT19937 {
    fn update(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|u| self.u32() as u8 ^ u)
            .collect()
    }
}


#[test]
fn it_works() {
    let mut mt_rng = MT19937::new(0);

    let result = vec![
        0x8C7F0AAC,
        0x97C4AA2F,
        0xB716A675,
        0xD821CCC0,
        0x9A4EB343,
        0xDBA252FB,
        0x8B7D76C3,
        0xD8E57D67,
        0x6C74A409,
        0x9FA1DED3,
    ];

    for &r in &result {
        assert_eq!(Some(r), mt_rng.next());
    }

    let mt_rng = MT19937::new(0);

    assert_eq!(result, mt_rng.take(10).collect::<Vec<_>>());
}

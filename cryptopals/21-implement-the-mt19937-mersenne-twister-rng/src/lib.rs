use std::num::Wrapping;


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

    fn gen(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) + (self.mt[(i+1) % 264] & 0x7fffffff);
            self.mt[i] = self.mt[(i+397) % 624] ^ (y >> 1);
            if (y % 2) != 0 {
                self.mt[i] = self.mt[i] ^ 2567483615;
            }
        }
    }

    pub fn next(&mut self) -> u32 {
        if self.index == 0 {
            self.gen();
        }

        let mut y = self.mt[self.index];
        y ^= y >> 11;
        y ^= (y << 7) & 2636928640;
        y ^= (y << 15) & 4022730752;
        y ^= y >> 18;

        self.index = (self.index + 1) % self.mt.len();

        y
    }
}

#[test]
fn it_works() {
    let mut mt_rng = MT19937::new(0);

    let result = [
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
        assert_eq!(r, mt_rng.next());
    }
}

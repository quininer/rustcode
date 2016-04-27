pub struct RC4 {
    state: [u8; 256],
    i: u8,
    j: u8
}

impl RC4 {
    pub fn new(key: &[u8]) -> RC4 {
        let mut state: [u8; 256] = [0; 256];
        let mut j: u8 = 0;

        for i in 0..state.len() {
            state[i] = i as u8;
        }
        for i in 0..state.len() {
            j = j.wrapping_add(state[i])
                .wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }

        RC4 { state: state, i: 0, j: 0 }
    }

    pub fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);

        let i = self.state[self.i as usize]
            .wrapping_add(self.state[self.j as usize]);
        self.state[i as usize]
    }
}

impl Iterator for RC4 {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        Some(RC4::next(self))
    }
}


#[test]
fn test_stream_cipher() {
    use implement_ctr_the_stream_cipher_mode::StreamCipher;

    assert_eq!(
        RC4::new(b"Key").update(b"Plaintext"),
        [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
    );
    assert_eq!(
        RC4::new(b"Wiki").update(b"pedia"),
        [0x10, 0x21, 0xbf, 0x04, 0x20]
    );
    assert_eq!(
        RC4::new(b"Secret").update(b"Attack at dawn"),
        [0x45, 0xa0, 0x1f, 0x64, 0x5f, 0xc3, 0x5b, 0x38, 0x35, 0x52, 0x54, 0x4b, 0x9b, 0xf5]
    );

    let key = rand!(rand!(choose 1..256));
    let plaintext = rand!(rand!(choose 25..250));
    assert_eq!(
        RC4::new(&key).update(&RC4::new(&key).update(&plaintext)),
        plaintext
    );
}

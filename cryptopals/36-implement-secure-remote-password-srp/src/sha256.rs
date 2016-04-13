use std::hash::Hasher as TraitHasher;
use std::io::Write;
use openssl::crypto::hash::{ Type, hash, Hasher };
use implement_a_sha_1_keyed_mac::Digest;
use implement_and_break_hmac_sha1_with_an_artificial_timing_leak::hmac;


pub struct Sha256(Hasher);

impl Default for Sha256 {
    fn default() -> Self {
        Sha256(Hasher::new(Type::SHA256))
    }
}

impl Sha256 {
    pub fn new() -> Self { Sha256::default() }
}

impl Digest for Sha256 {
    fn bs() -> usize { 256 }
    fn digest(&mut self) -> Vec<u8> {
        self.0.finish()
    }
    fn hash(bytes: &[u8]) -> Vec<u8> {
        hash(Type::SHA256, bytes)
    }
}

impl TraitHasher for Sha256 {
    #[allow(unused_must_use)]
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<Sha256>(key, message)
}

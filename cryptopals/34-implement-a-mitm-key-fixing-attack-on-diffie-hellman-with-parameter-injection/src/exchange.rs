use num::BigUint;
use implement_cbc_mode::AesCBC;
use implement_a_sha_1_keyed_mac::{ Sha1, Digest };
use implement_diffie_hellman::{ DH, NumExchange };


pub trait Exchange: NumExchange {
    fn from_data(p: &[u8], g: &[u8], token: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (public, secret) = Self::from_num(
            &BigUint::from_bytes_be(p),
            &BigUint::from_bytes_be(g),
            &BigUint::from_bytes_be(token)
        );
        (public.to_bytes_be(), secret.to_bytes_be())
    }
    fn public(&self) -> Vec<u8> {
        self.num_public().to_bytes_be()
    }
    fn exchange(&self, token: &[u8]) -> Vec<u8> {
        self.num_exchange(&BigUint::from_bytes_be(token))
            .to_bytes_be()
    }
}

impl Exchange for DH {}

pub trait GenCrypter: Exchange {
    fn handshake_read(&self, token: &[u8], iv: &[u8]) -> AesCBC {
        AesCBC::new(
            &Sha1::hash(&self.exchange(token))[..16],
            iv
        )
    }
    fn handshake(p: &[u8], g: &[u8], token: &[u8]) -> (AesCBC, Vec<u8>, Vec<u8>) {
        let (pk, sk) = Self::from_data(p, g, token);
        let iv = rand!();
        (
            AesCBC::new(&Sha1::hash(&sk)[..16], &iv),
            pk,
            iv
        )
    }
}

impl GenCrypter for DH {}

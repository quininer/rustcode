use num::BigUint;
use implement_cbc_mode::AesCBC;
use implement_a_sha_1_keyed_mac::{ Sha1, Digest };
use implement_diffie_hellman::{ DH, NumExchange };


pub trait Exchange: NumExchange {
    fn data_pk_gen(p: &[u8], g: &[u8], pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (public, secret) = Self::num_pk_gen(
            &BigUint::from_bytes_be(p),
            &BigUint::from_bytes_be(g),
            &BigUint::from_bytes_be(pk)
        );
        (public.to_bytes_be(), secret.to_bytes_be())
    }
    fn secret(&self) -> Vec<u8> {
        self.num_secret().to_bytes_be()
    }
    fn public(&self) -> Vec<u8> {
        self.num_public().to_bytes_be()
    }
    fn exchange(&self, pk: &[u8]) -> Vec<u8> {
        self.num_exchange(&BigUint::from_bytes_be(pk))
            .to_bytes_be()
    }
}

impl<T: NumExchange> Exchange for T {}

pub trait GenCrypter: Exchange {
    fn handshake_read(&self, pk: &[u8], iv: &[u8]) -> AesCBC {
        AesCBC::new(
            &Sha1::hash(&self.exchange(pk))[..16],
            iv
        )
    }
    fn handshake(p: &[u8], g: &[u8], pk: &[u8]) -> (AesCBC, Vec<u8>, Vec<u8>) {
        let (pk, sk) = Self::data_pk_gen(p, g, pk);
        let iv = rand!();
        (
            AesCBC::new(&Sha1::hash(&sk)[..16], &iv),
            pk,
            iv
        )
    }
}

impl GenCrypter for DH {}

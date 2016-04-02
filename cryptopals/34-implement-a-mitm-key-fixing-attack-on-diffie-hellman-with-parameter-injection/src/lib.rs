extern crate num;
extern crate implement_diffie_hellman;
extern crate implement_cbc_mode;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate an_ebccbc_detection_oracle;

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
    fn handshake_read(&self, token: &[u8]) -> AesCBC {
        AesCBC::new(
            &Sha1::hash(&self.exchange(token))[..16],
            &[0; 16]
        )
    }
    fn handshake(p: &[u8], g: &[u8], token: &[u8]) -> (AesCBC, Vec<u8>) {
        let (pk, sk) = Self::from_data(p, g, token);
        (
            AesCBC::new(&Sha1::hash(&sk)[..16], &[0; 16]),
            pk
        )
    }
}

impl GenCrypter for DH {}

#[test]
fn test_dh_aescbc() {
    use implement_cbc_mode::Mode;
    use implement_diffie_hellman::{ P, G };

    let plaintext = b"YELLOW SUBMARINE";

    let alice = DH::default();
    let handshake_args = (
        P.to_bytes_be(),
        G.to_bytes_be(),
        alice.public()
    );
    let (mut bob_aes, token) = DH::handshake(
        &handshake_args.0,
        &handshake_args.1,
        &handshake_args.2
    );

    let ciphertext = bob_aes.update(Mode::Encrypt, plaintext);
    assert_eq!(
        alice.handshake_read(&token).update(Mode::Decrypt, &ciphertext),
        plaintext.to_vec()
    );
}

#[test]
fn it_works() {
    use implement_cbc_mode::Mode;
    use implement_diffie_hellman::{ P, G };

    let plaintext = b"YELLOW SUBMARINE";

    let alice = DH::default();
    let handshake_args = (
        P.to_bytes_be(),
        G.to_bytes_be(),
        alice.public()
    );

    // mitm
    let bad_handshake_args = (
        handshake_args.0.clone(),
        handshake_args.1,
        handshake_args.0.clone()
    );

    let (mut bob_aes, token) = DH::handshake(
        &bad_handshake_args.0,
        &bad_handshake_args.1,
        &bad_handshake_args.2
    );

    // mitm
    let bad_token = bad_handshake_args.2;

    let ciphertext = bob_aes.update(Mode::Encrypt, plaintext);
    assert_eq!(
        alice.handshake_read(&bad_token).update(Mode::Decrypt, &ciphertext),
        plaintext.to_vec()
    );
}

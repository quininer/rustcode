extern crate implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection;
extern crate implement_diffie_hellman;
extern crate implement_cbc_mode;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate an_ebccbc_detection_oracle;


#[test]
fn it_work() {
    use implement_a_sha_1_keyed_mac::{ Sha1, Digest };
    use implement_cbc_mode::{ AesCBC, Mode };
    use implement_diffie_hellman::{ DH, P, ONE, ZERO };
    use implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection::{
        GenCrypter, Exchange
    };

    let plaintext = b"YELLOW SUBMARINE";
    let p = P.to_bytes_be();
    for &(ref g, ref guess) in &[
        (ONE.to_bytes_be(), vec![ONE.to_bytes_be()]),
        (P.to_bytes_be(), vec![ZERO.to_bytes_be()]),
        ((P.clone() - ONE.clone()).to_bytes_be(), vec![ONE.to_bytes_be(), (P.clone() - ONE.clone()).to_bytes_be()])
    ] {
        let iv = rand!();
        let alice = DH::default();

        // mitmp
        let bob = DH::new_data(&p, &g);

        let mut alice_aes = alice.handshake_read(&bob.public(), &iv);
        let mut bob_aes = bob.handshake_read(&alice.public(), &iv);

        let ciphertext = alice_aes.update(Mode::Encrypt, plaintext);
        let bob_text = bob_aes.update(Mode::Decrypt, &ciphertext);
        alice_aes.set_iv(&iv);
        bob_aes.set_iv(&iv);
        assert_eq!(
            alice_aes.update(Mode::Decrypt, &bob_aes.update(Mode::Encrypt, &bob_text)),
            plaintext
        );

        // mitm decryption
        assert!(guess.iter().any(|k| {
            AesCBC::new(&Sha1::hash(&k)[..16], &iv)
                .update(Mode::Decrypt, &ciphertext)
            ==
            plaintext
        }));
    }
}

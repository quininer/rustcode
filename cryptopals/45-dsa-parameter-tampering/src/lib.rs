extern crate dsa_key_recovery_from_nonce;
extern crate bleichenbachers_e_eq_3_rsa_attack;
extern crate implement_diffie_hellman;


#[test]
fn test_g_is_zero() {
    use dsa_key_recovery_from_nonce::{ DSA, P, Q };
    use bleichenbachers_e_eq_3_rsa_attack::Signer;
    use implement_diffie_hellman::ZERO;

    let message1 = b"Hello, world";
    let message2 = b"Goodbye, world";

    let dsa = DSA::new(&P, &Q, &ZERO);
    let pk = dsa.public();

    let signature1 = dsa.sign(message1);
    let signature2 = dsa.sign(message2);

    assert!(pk.verify(message1, &signature1));
    assert!(pk.verify(message2, &signature2));

    assert!(pk.verify(message1, &signature2));
    assert!(pk.verify(message2, &signature1));
}

#[test]
fn test_g_is_pplusone() {
    use dsa_key_recovery_from_nonce::{ DSA, P, Q };
    use bleichenbachers_e_eq_3_rsa_attack::Signer;
    use implement_diffie_hellman::ONE;

    let message1 = b"Hello, world";
    let message2 = b"Goodbye, world";

    let dsa = DSA::new(&P, &Q, &(P.clone() + ONE.clone()));
    let pk = dsa.public();

    let signature1 = dsa.sign(message1);
    let signature2 = dsa.sign(message2);

    assert!(pk.verify(message1, &signature1));
    assert!(pk.verify(message2, &signature2));

    assert!(pk.verify(message1, &signature2));
    assert!(pk.verify(message2, &signature1));
}

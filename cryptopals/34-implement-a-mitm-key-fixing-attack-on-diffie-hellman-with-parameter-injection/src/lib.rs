extern crate num;
extern crate implement_diffie_hellman;
extern crate implement_cbc_mode;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate an_ebccbc_detection_oracle;

mod message;
mod exchange;

pub use message::Message;
pub use exchange::{ Exchange, GenCrypter };


#[test]
fn test_message() {
    use std::thread;
    use std::sync::mpsc::channel;
    use implement_cbc_mode::Mode;
    use implement_diffie_hellman::{ DH, P, G };

    let plaintext = b"YELLOW SUBMARINE";
    let (alice_channel, alice) = channel::<Message>();
    let (bob_channel, bob) = channel::<Message>();
    let alice_channel_start = alice_channel.clone();

    let alice_thread = thread::spawn(move || {
        let mut alice_dh = None;
        loop {
            match alice.recv() {
                Ok(Message::Start) => {
                    alice_dh = Some(DH::default());
                    bob_channel.send(Message::HandshakeAll(
                        P.to_bytes_be(),
                        G.to_bytes_be(),
                        alice_dh.clone().unwrap().public()
                    )).ok();
                },
                Ok(Message::MessageAll(pk, iv, ciphertext)) => {
                    if let Some(dh) = alice_dh.clone() {
                        let mut alice_aes = dh.handshake_read(&pk, &iv);
                        assert_eq!(
                            alice_aes.update(Mode::Decrypt, &ciphertext),
                            plaintext
                        );
                        break
                    }
                }
                _ => panic!()
            }
        };
        true
    });

    thread::spawn(move || loop {
        match bob.recv() {
            Ok(Message::HandshakeAll(p, g, pk)) => {
                let (mut bob_aes, pk, iv) = DH::handshake(
                    &p,
                    &g,
                    &pk
                );
                alice_channel.send(Message::MessageAll(
                    pk,
                    iv,
                    bob_aes.update(Mode::Encrypt, plaintext)
                )).ok();
            },
            _ => break
        }
    });

    alice_channel_start.send(Message::Start).ok();
    assert!(alice_thread.join().unwrap_or(false));
}


#[test]
fn test_mitm() {
    use std::thread;
    use std::sync::mpsc::channel;
    use implement_cbc_mode::Mode;
    use implement_diffie_hellman::{ DH, P, G };

    let plaintext = b"YELLOW SUBMARINE";
    let (alice_channel, alice) = channel::<Message>();
    let (bob_channel, bob) = channel::<Message>();
    let (mallory_channel, mallory) = channel::<Message>();
    let alice_channel_start = alice_channel.clone();

    let alice_mallory_channel = mallory_channel.clone();
    let alice_thread = thread::spawn(move || {
        let mut alice_dh = None;
        loop {
            match alice.recv() {
                Ok(Message::Start) => {
                    alice_dh = Some(DH::default());
                    alice_mallory_channel.send(Message::HandshakeAll(
                        P.to_bytes_be(),
                        G.to_bytes_be(),
                        alice_dh.clone().unwrap().public()
                    )).ok();
                },
                Ok(Message::MessageAll(pk, iv, ciphertext)) => {
                    if let Some(dh) = alice_dh.clone() {
                        let mut alice_aes = dh.handshake_read(&pk, &iv);
                        assert_eq!(
                            alice_aes.update(Mode::Decrypt, &ciphertext),
                            plaintext
                        );
                        break
                    }
                }
                _ => panic!()
            }
        };
        true
    });

    let bob_mallory_channel = mallory_channel.clone();
    thread::spawn(move || loop {
        match bob.recv() {
            Ok(Message::HandshakeAll(p, g, pk)) => {
                let (mut bob_aes, pk, iv) = DH::handshake(
                    &p,
                    &g,
                    &pk
                );
                bob_mallory_channel.send(Message::MessageAll(
                    pk,
                    iv,
                    bob_aes.update(Mode::Encrypt, plaintext)
                )).ok();
            },
            _ => break
        }
    });

    thread::spawn(move || {
        let mut mp = None;
        loop {
            match mallory.recv() {
                Ok(Message::HandshakeAll(p, g, _)) => {
                    mp = Some(p.clone());
                    bob_channel.send(Message::HandshakeAll(
                        p.clone(), g, p
                    )).ok();
                },
                Ok(Message::MessageAll(_, iv, ciphertext)) => {
                    alice_channel.send(Message::MessageAll(
                        mp.clone().unwrap(), iv, ciphertext
                    )).ok();
                }
                _ => break
            }
        }
    });

    alice_channel_start.send(Message::Start).ok();
    assert!(alice_thread.join().unwrap_or(false));
}

use std::sync::mpsc::{ channel, Sender, Receiver };
use num::BigUint;
use rustc_serialize::hex::FromHex;
use implement_diffie_hellman::{ G, modexp };
use implement_a_sha_1_keyed_mac::Digest;
use super::{ Sha256, hmac_sha256 };


lazy_static!{
    pub static ref N: BigUint = "
000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffff"
        .from_hex().ok()
        .map(|n| BigUint::from_bytes_be(&n))
        .unwrap();
    pub static ref K: BigUint = BigUint::from(3u32);
}


#[derive(Debug, Clone)]
pub enum Message {
    Start,
    /// email, DH pk
    Login(Vec<u8>, Vec<u8>),
    /// salt, DH pk
    Exchange(Vec<u8>, Vec<u8>),
    /// salt, DH pk, u
    UExchange(Vec<u8>, Vec<u8>, Vec<u8>),
    /// HMAC value
    HMAC(Vec<u8>),
    /// validate ok
    Ok,
    Fail
}

pub struct Server {
    email: Vec<u8>,
    channel: Receiver<Message>,
    salt: Vec<u8>,
    v: BigUint,
}

impl Server {
    pub fn new(email: &[u8], password: &[u8]) -> (Server, Sender<Message>) {
        let (sender, receiver) = channel();
        let salt = rand!(32);
        let x = BigUint::from_bytes_be(&Sha256::hash(&[&salt, password].concat()));
        let v = modexp(&G, &x, &N);

        (
            Server {
                email: email.into(),
                channel: receiver,
                salt: salt,
                v: v
            },
            sender
        )
    }

    pub fn run(&self, sender: Sender<Message>) -> bool {
        let bob_sk = rand_big!(&N);
        let bob_pk = K.clone() * self.v.clone() + modexp(&G, &bob_sk, &N);
        let mut u = None;
        let mut alice_pk_save = None;
        loop {
            match self.channel.recv() {
                Ok(Message::Login(email, alice_pk)) => {
                    assert_eq!(email, self.email.clone());

                    u = Some(BigUint::from_bytes_be(&Sha256::hash(&[
                        alice_pk.clone(),
                        bob_pk.to_bytes_be()
                    ].concat())));
                    alice_pk_save = Some(BigUint::from_bytes_be(&alice_pk));

                    sender.send(Message::Exchange(
                        self.salt.clone(),
                        bob_pk.to_bytes_be()
                    )).ok();
                },
                Ok(Message::HMAC(value)) => {
                    // NOTE (A * v**u) ** b % N
                    // if A = 0 ?
                    // if A = N**_ ?
                    let s = modexp(
                        &(
                            alice_pk_save.clone().unwrap()
                                * modexp(&self.v, &u.unwrap(), &N)
                        ),
                        &bob_sk,
                        &N
                    );
                    let k = Sha256::hash(&s.to_bytes_be());
                    let hmac_value = hmac_sha256(&k, &self.salt);

                    sender.send(if hmac_value == value {
                        Message::Ok
                    } else {
                        Message::Fail
                    }).ok();
                    return true;
                },
                _ => unreachable!()
            }
        }
    }
}

pub struct Client {
    email: Vec<u8>,
    password: Vec<u8>,
    channel: Receiver<Message>
}

impl Client {
    pub fn new(email: &[u8], password: &[u8]) -> (Client, Sender<Message>) {
        let (sender, receiver) = channel();
        (
            Client {
                email: email.into(),
                password: password.into(),
                channel: receiver
            },
            sender
        )
    }

    pub fn run(&self, sender: Sender<Message>) -> bool {
        let alice_sk = rand_big!(&N);
        let alice_pk = modexp(&G, &alice_sk, &N);
        loop {
            match self.channel.recv() {
                Ok(Message::Start) => {
                    sender.send(Message::Login(
                        self.email.clone(),
                        alice_pk.to_bytes_be()
                    )).ok();
                },
                Ok(Message::Exchange(salt, bob_pk)) => {
                    let u = BigUint::from_bytes_be(&Sha256::hash(&[
                        alice_pk.to_bytes_be(),
                        bob_pk.clone()
                    ].concat()));
                    let x = BigUint::from_bytes_be(&Sha256::hash(&[
                        salt.clone(),
                        self.password.clone()
                    ].concat()));
                    let s = modexp(
                        &(
                            BigUint::from_bytes_be(&bob_pk)
                                - K.clone() * modexp(&G, &x, &N)
                        ),
                        &(&alice_sk + &u * &x),
                        &N
                    );
                    sender.send(Message::HMAC(hmac_sha256(
                        &Sha256::hash(&s.to_bytes_be()),
                        &salt
                    ))).ok();
                },
                Ok(Message::Ok) => return true,
                Ok(Message::Fail) => return false,
                _ => unreachable!()
            }
        }
    }
}

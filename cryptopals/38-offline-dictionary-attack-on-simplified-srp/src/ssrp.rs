use std::sync::mpsc::{ channel, Sender, Receiver };
use num::BigUint;
use implement_diffie_hellman::{ modexp, G };
use implement_a_sha_1_keyed_mac::Digest;
use implement_secure_remote_password_srp::{ Message, N, Sha256, hmac_sha256 };


pub struct Server {
    email: Vec<u8>,
    channel: Receiver<Message>,
    salt: Vec<u8>,
    v: BigUint
}

impl Server {
    pub fn new(email: &[u8], password: &[u8]) -> (Server, Sender<Message>) {
        let (sender, receiver) = channel();
        let salt = rand!(32);
        let x = Sha256::hash(&[
            &salt,
            password
        ].concat());
        let v = modexp(&G, &BigUint::from_bytes_be(&x), &N);
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
        let bob_pk = modexp(&G, &bob_sk, &N);
        let u = rand!(128);
        let mut alice_pk_save = None;
        loop {
            match self.channel.recv() {
                Ok(Message::Login(email, alice_pk)) => {
                    assert_eq!(email, self.email.clone());

                    alice_pk_save = Some(BigUint::from_bytes_be(&alice_pk));
                    sender.send(Message::UExchange(
                        self.salt.clone(),
                        bob_pk.to_bytes_be(),
                        u.clone()
                    )).ok();
                },
                Ok(Message::HMAC(value)) => {
                    let s = modexp(
                        &(
                            alice_pk_save.clone().unwrap() * modexp(
                                &self.v, &BigUint::from_bytes_be(&u), &N
                            )
                        ),
                        &bob_sk,
                        &N
                    );
                    let k = Sha256::hash(&s.to_bytes_be());
                    let hmac_value = hmac_sha256(
                        &k,
                        &self.salt
                    );
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
                Ok(Message::UExchange(salt, bob_pk, u)) => {
                    let x = BigUint::from_bytes_be(&Sha256::hash(&[
                        salt.clone(),
                        self.password.clone()
                    ].concat()));
                    let s = modexp(
                        &BigUint::from_bytes_be(&bob_pk),
                        &(&alice_sk + BigUint::from_bytes_be(&u) * x),
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


#[test]
fn tset_simplified_srp() {
    use std::thread::spawn;

    let (server, server_channel) = Server::new(
        b"alice@bob.com",
        b"imalice"
    );
    let (client, client_channel) = Client::new(
        b"alice@bob.com",
        b"imalice"
    );

    client_channel.send(Message::Start).ok();

    let server_task = spawn(move || server.run(client_channel));
    assert!(spawn(move || client.run(server_channel)).join().unwrap());
    assert!(server_task.join().unwrap());
}

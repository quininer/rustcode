extern crate num;
extern crate implement_secure_remote_password_srp;
extern crate implement_a_sha_1_keyed_mac;
#[macro_use] extern crate implement_diffie_hellman;
#[macro_use] extern crate an_ebccbc_detection_oracle;

mod ssrp;

use std::sync::mpsc::{ channel, Sender, Receiver };
use num::BigUint;
use implement_a_sha_1_keyed_mac::Digest;
use implement_diffie_hellman::{ modexp, G };
use implement_secure_remote_password_srp::{
    Message, N,
    Sha256, hmac_sha256
};
pub use ssrp::{ Server, Client };


pub struct DarkBob {
    email: Vec<u8>,
    channel: Receiver<Message>,
    salt: Vec<u8>
}

impl DarkBob {
    pub fn new(email: &[u8]) -> (DarkBob, Sender<Message>) {
        let (sender, receiver) = channel();
        let salt = rand!(32);
        (
            DarkBob {
                email: email.into(),
                channel: receiver,
                salt: salt
            },
            sender
        )
    }

    pub fn run(&self, sender: Sender<Message>) -> (
        Vec<u8>, // hash
        Vec<u8>, // salt
        BigUint, // alice_pk
        BigUint, // bob_sk
        BigUint, // u
        BigUint, // N
    ) {
        let bob_sk = rand_big!(&N);
        let bob_pk = modexp(G.clone(), bob_sk.clone(), N.clone());
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
                    sender.send(Message::Fail).ok();
                    return (
                        value,
                        self.salt.clone(),
                        alice_pk_save.clone().unwrap(),
                        bob_sk.clone(),
                        BigUint::from_bytes_be(&u),
                        N.clone()
                    );
                },
                _ => unreachable!()
            }
        }
    }
}

pub fn password_hash(
    password: &[u8],
    salt: &[u8],
    alice_pk: &BigUint,
    bob_sk: &BigUint,
    u: &BigUint,
    n: &BigUint
) -> Vec<u8> {
    let x = Sha256::hash(&[salt, password].concat());
    let v = modexp(G.clone(), BigUint::from_bytes_be(&x), n.clone());
    let s = modexp(
        alice_pk.clone() * modexp(v.clone(), u.clone(), n.clone()),
        bob_sk.clone(),
        n.clone()
    );
    let k = Sha256::hash(&s.to_bytes_be());
    hmac_sha256(&k, salt)
}


#[test]
fn it_works() {
    use std::thread::spawn;

    let dict: Vec<Vec<u8>> = vec![
        "imbob".into(),
        "uarealice".into(),
        "imalice".into(),
    ];
    let email = b"alice@bob.com";
    let password = b"imalice";

    let (evil_server, server_channel) = DarkBob::new(email);
    let (client, client_channel) = Client::new(email, password);

    client_channel.send(Message::Start).ok();
    let bob_task = spawn(move || evil_server.run(client_channel));
    assert!(!spawn(move || client.run(server_channel)).join().unwrap());

    let (hash, salt, alice_pk, bob_sk, u, n) = bob_task.join().unwrap();
    let guess_password = dict.iter()
        .find(move |&word| password_hash(
            &word,
            &salt,
            &alice_pk,
            &bob_sk,
            &u,
            &n
        ) == hash)
        .unwrap();

    assert_eq!(guess_password, password);
}
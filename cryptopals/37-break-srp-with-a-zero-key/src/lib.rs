extern crate num;
extern crate implement_secure_remote_password_srp;
extern crate implement_diffie_hellman;
extern crate implement_a_sha_1_keyed_mac;

use std::sync::mpsc::{ channel, Sender, Receiver };
use num::BigUint;
use implement_a_sha_1_keyed_mac::Digest;
use implement_diffie_hellman::ZERO;
use implement_secure_remote_password_srp::{
    Message,
    Sha256, hmac_sha256
};


pub struct ScarletAlice {
    email: Vec<u8>,
    channel: Receiver<Message>,
    parm: Vec<u8>
}

impl ScarletAlice {
    pub fn new(email: &[u8], parm: &BigUint) -> (ScarletAlice, Sender<Message>) {
        let (sender, receiver) = channel();
        (
            ScarletAlice {
                email: email.into(),
                channel: receiver,
                parm: parm.to_bytes_be()
            },
            sender
        )
    }

    pub fn run(&self, sender: Sender<Message>) -> bool {
        loop {
            match self.channel.recv() {
                Ok(Message::Start) => {
                    sender.send(Message::Login(
                        self.email.clone(),
                        self.parm.clone()
                    )).ok();
                },
                Ok(Message::Exchange(salt, _)) => {
                    let k = Sha256::hash(&ZERO.to_bytes_be());
                    sender.send(Message::HMAC(hmac_sha256(
                        &k,
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
fn test_0_parm() {
    use std::thread::spawn;
    use implement_secure_remote_password_srp::Server;

    let (server, server_channel) = Server::new(
        b"alice@bob.com",
        b"-- bi --"
    );
    let (evil_client, client_channel) = ScarletAlice::new(
        b"alice@bob.com",
        &ZERO
    );

    client_channel.send(Message::Start).ok();

    let server_task = spawn(move || server.run(client_channel));
    assert!(spawn(move || evil_client.run(server_channel)).join().unwrap());
    assert!(server_task.join().unwrap());
}

#[test]
fn test_n_parm() {
    use std::thread::spawn;
    use implement_secure_remote_password_srp::{ Server, N };

    let (server, server_channel) = Server::new(
        b"alice@bob.com",
        b"-- bibibi --"
    );
    let (evil_client, client_channel) = ScarletAlice::new(
        b"alice@bob.com",
        &N
    );

    client_channel.send(Message::Start).ok();

    let server_task = spawn(move || server.run(client_channel));
    assert!(spawn(move || evil_client.run(server_channel)).join().unwrap());
    assert!(server_task.join().unwrap());
}

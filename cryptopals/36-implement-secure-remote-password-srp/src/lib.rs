extern crate num;
extern crate openssl;
extern crate rustc_serialize;
extern crate implement_a_sha_1_keyed_mac;
extern crate implement_and_break_hmac_sha1_with_an_artificial_timing_leak;
extern crate implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate implement_diffie_hellman;
#[macro_use] extern crate an_ebccbc_detection_oracle;

mod sha256;
mod message;

pub use message::{ Message, Server, Client };
pub use sha256::{ Sha256, hmac_sha256 };


#[test]
fn it_works() {
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

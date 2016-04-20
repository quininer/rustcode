#![feature(question_mark)]

extern crate implement_cbc_mode;
extern crate implement_pkcs7_padding;
extern crate ecb_cut_and_paste;
#[macro_use] extern crate an_ebccbc_detection_oracle;
#[macro_use] extern crate fixed_xor;
#[macro_use] extern crate maplit;

use std::collections::HashMap;
use implement_cbc_mode::{ AesCBC, Mode };
use implement_pkcs7_padding::pkcs7padding;
use ecb_cut_and_paste::parse_profile;


pub fn aescbc_mac(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let out = AesCBC::new(key, iv)
        .update(Mode::Encrypt, &pkcs7padding(data, key.len()));
    out[out.len()-key.len()..].into()
}


pub struct BankServer {
    key: Vec<u8>
}

impl BankServer {
    pub fn new(key: &[u8]) -> BankServer {
        BankServer { key: key.into() }
    }

    pub fn verify_api(&self, data: &[u8]) -> Result<HashMap<String, String>, ()> {
        let mac = &data[data.len()-16..];
        let iv = &data[data.len()-32..data.len()-16];
        let message = &data[..data.len()-32];
        if aescbc_mac(&self.key, iv, message) == mac {
            Ok(parse_profile(message))
        } else {
            Err(())
        }
    }

    pub fn remittance_api(&self, from: &str, to: &str, amount: usize) -> Result<Vec<u8>, ()> {
        if from != "charlie" { Err(())? };
        let iv = rand!(self.key.len());
        let message = format!(
            "from={}&to={}&amount={}",
            from.replace('&', "%26").replace('=', "%3d"),
            to.replace('&', "%26").replace('=', "%3d"),
            amount
        ).into_bytes();
        let mac = aescbc_mac(&self.key, &iv, &message);
        Ok([message, iv, mac].concat())
    }

    pub fn new_verify_api(&self, data: &[u8]) -> Result<(String, HashMap<String, usize>), ()> {
        let (message, mac) = data.split_at(data.len()-16);
        let msg = parse_profile(message);
        let from = &msg["from"];
        let toamount = msg["tx_list"].split(';')
            .map(|r| {
                let mut r = r.split(':');
                (
                    r.next().unwrap().to_string(),
                    r.next().and_then(|n| n.parse().ok()).unwrap_or(0usize)
                )
            })
            .collect();
        if aescbc_mac(&self.key, &[0; 16], message) == mac {
            Ok((from.to_string(), toamount))
        } else {
            Err(())
        }
    }

    fn inner_remittance_api(&self, from: &str, toamount: HashMap<String, usize>) -> Vec<u8> {
        let mut message = format!(
            "from={}&tx_list=",
            from.replace('&', "%26").replace('=', "%3d").replace(':', "%3a").replace(';', "%3b")
        );
        for (to, amount) in &toamount {
            message.push_str(&format!(
                "{}:{};",
                to.replace('&', "%26").replace('=', "%3d").replace(':', "%3a").replace(';', "%3b"),
                amount
            ));
        };
        let message: Vec<u8> = message[..message.len()-1].into();
        let mac = aescbc_mac(&self.key, &[0; 16], &message);
        [message, mac].concat()
    }

    pub fn new_remittance_api(&self, from: &str, toamount: HashMap<String, usize>) -> Result<Vec<u8>, ()> {
        if from != "charlie" && from != "cc" { Err(())? };
        Ok(self.inner_remittance_api(from, toamount))
    }

    pub fn bob_remittance_api(&self) -> Vec<u8> {
        self.inner_remittance_api("bob", hashmap!{ String::from("alice") => 1 })
    }
}


#[test]
fn test_forgery_with_iv() {
    let forgery_message = b"from=bob&&&&&to=alice&amount=1000000";
    let bank = BankServer::new(&rand!(16));

    let data = bank.remittance_api("charlie", "alice", 1000000).unwrap();
    let message = &data[..data.len()-32];
    let iv = &data[data.len()-32..data.len()-16];
    let mac = &data[data.len()-16..];

    let new_iv = xor!(
        &forgery_message[..16],
        &message[..16],
        iv
    );

    let info = bank.verify_api(&[
        forgery_message.to_vec(),
        new_iv,
        mac.into()
    ].concat()).unwrap();
    assert_eq!(info["from"], "bob");
    assert_eq!(info["to"], "alice");
    assert_eq!(info["amount"], "1000000");
}

#[test]
fn test_forgery_with_noiv() {
    let bank = BankServer::new(&rand!(16));

    let data = bank.bob_remittance_api();
    let (message, mac) = data.split_at(data.len()-16);

    let charlie_data = bank.new_remittance_api("cc", hashmap!{
        String::from("aa") => 1,
        String::from("alice") => 1000000
    }).unwrap();
    let (from, tx_list) = bank.new_verify_api(&[
        pkcs7padding(&message, 16),
        xor!(mac, &charlie_data[..16]),
        charlie_data[16..].into()
    ].concat()).unwrap();

    assert_eq!(from, "bob");
    assert_eq!(tx_list["alice"], 1000000);
}

#[test]
fn test_bank() {
    let bank = BankServer::new(&rand!(16));
    let data = bank.remittance_api("charlie", "alice", 1).unwrap();
    let info = bank.verify_api(&data).unwrap();
    assert_eq!(info["from"], "charlie");
    assert_eq!(info["to"], "alice");
    assert_eq!(info["amount"], String::from("1"));

    let data = bank.new_remittance_api("charlie", hashmap!{ String::from("alice") => 1 }).unwrap();
    let (from, tx_list) = bank.new_verify_api(&data).unwrap();
    assert_eq!(from, "charlie");
    assert_eq!(tx_list["alice"], 1);

    assert!(bank.remittance_api("bob", "alice", 1).is_err());
    assert!(bank.new_remittance_api("bob", hashmap!{ String::from("alice") => 1 }).is_err());
}

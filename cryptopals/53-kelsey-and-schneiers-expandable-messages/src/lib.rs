extern crate num;
extern crate implement_diffie_hellman;
extern crate implement_and_break_hmac_sha1_with_an_artificial_timing_leak;
extern crate iterated_hash_function_multicollisions;
#[macro_use] extern crate an_ebccbc_detection_oracle;

use std::collections::HashMap;
use num::{ range, pow };
use implement_and_break_hmac_sha1_with_an_artificial_timing_leak::rightpad;
use implement_diffie_hellman::{ ZERO, TWO };
use iterated_hash_function_multicollisions::{ B, H, HashFn };


pub fn state_collision(alpha: usize, is: &[u8], md: &HashFn) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ()> {
    let hashes: HashMap<Vec<u8>, Vec<u8>> = range(ZERO.clone(), pow(TWO.clone(), B))
        .map(|r| rightpad(&r.to_bytes_le(), B))
        .map(|r| (md(&r, is), r.into()))
        .collect();

    let dummy = vec![0; B * alpha];
    let dummy_state = md(&dummy, is);
    for b in range(ZERO.clone(), pow(TWO.clone(), B)) {
        let b = rightpad(&b.to_bytes_le(), B);
        let dummy_hash = md(&b, &dummy_state);
        if let Some(message) = hashes.get(&dummy_hash) {
            return Ok((dummy_hash, message.clone(), [dummy, b].concat()))
        }
    }
    Err(())
}

pub fn make_expandable(k: usize, is: &[u8], md: &HashFn) -> (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut expandable = Vec::new();
    let mut is: Vec<u8> = is.into();

    for i in 1..(k+1) {
        let (xis, message, dummy) = state_collision(2usize.pow((k-i) as u32), &is, md).unwrap();
        is = xis;
        expandable.push((message, dummy));
    }

    (is, expandable)
}

pub fn make_second_preimage(expandable: &[(Vec<u8>, Vec<u8>)], len: usize) -> Vec<u8> {
    let mut message = Vec::new();
    let k = expandable.len();
    assert!(k <= len / B && len / B <= k + 2usize.pow(k as u32) - 1);

    for (i, &(ref m, ref d)) in expandable.iter().enumerate() {
        if message.len() + d.len() + (k - i - 1) * B > len {
            assert_eq!(m.len(), B);
            message.append(&mut m.clone());
        } else {
            message.append(&mut d.clone());
        };
    }

    assert_eq!(message.len(), len);
    message
}

pub fn crack_md_preimage(k: usize, message: &[u8], md: HashFn) -> Vec<u8> {
    let hash_chunks: HashMap<Vec<u8>, usize> = message.chunks(B)
        .enumerate()
        .map(|(pos, b)| (b, pos * B))
        .scan(vec![0; H], |state, (b, pos)| {
            *state = md(b, state);
            Some(if pos > k * B {
                Some((state.clone(), pos))
            } else {
                None
            })
        })
        .filter_map(|x| x)
        .collect();

    let (fs, expandable) = make_expandable(k, &[], &md);
    assert_eq!(expandable.len(), k);

    let (bridge, pos) = range(ZERO.clone(), pow(TWO.clone(), B))
        .map(|n| rightpad(&n.to_bytes_le(), B))
        .find(|b| hash_chunks.get(&md(&b, &fs)).is_some())
        .map(|b| (b.clone(), *hash_chunks.get(&md(&b, &fs)).unwrap()))
        .unwrap();

    [
        make_second_preimage(&expandable, pos),
        bridge.clone(),
        message[pos+bridge.len()..].into()
    ].concat()
}


#[test]
fn it_works() {
    use iterated_hash_function_multicollisions::md_aes;

    let k = 8;
    let message = rand!(2usize.pow(k as u32));
    let collisions_message = crack_md_preimage(k, &message, Box::new(md_aes));

    assert!(message != collisions_message);
    assert_eq!(
        message.len(),
        collisions_message.len()
    );
    assert_eq!(
        md_aes(&message, &[]),
        md_aes(&collisions_message, &[])
    );
}

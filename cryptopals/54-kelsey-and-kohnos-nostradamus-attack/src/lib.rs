#![feature(slice_patterns)]

extern crate num;
extern crate implement_diffie_hellman;
extern crate implement_and_break_hmac_sha1_with_an_artificial_timing_leak;
extern crate iterated_hash_function_multicollisions;

use std::collections::HashMap;
use num::{ range, pow };
use implement_and_break_hmac_sha1_with_an_artificial_timing_leak::rightpad;
use implement_diffie_hellman::{ ZERO, ONE, TWO };
use iterated_hash_function_multicollisions::{ HashFn, B };


pub type CollectionTree = Vec<Vec<((Vec<u8>, Vec<u8>), Vec<u8>)>>;

pub fn pair_collisions(is1: &[u8], is2: &[u8], md: &HashFn) -> Result<((Vec<u8>, Vec<u8>), Vec<u8>), ()> {
    for i in range(ZERO.clone(), pow(TWO.clone(), B)) {
        let i = rightpad(&i.to_bytes_le(), B);
        for j in range(ZERO.clone(), pow(TWO.clone(), B)) {
            let j = rightpad(&j.to_bytes_le(), B);

            let h = md(&i, is1);
            if h == md(&j, is2) { return Ok(((i, j), h)) };

            let h = md(&i, is1);
            if h == md(&j, is2) { return Ok(((j, i), h)) };
        }
    }

    Err(())
}

pub fn gen_predicted_hash(k: usize, md: HashFn) -> (Vec<u8>, CollectionTree) {
    let leaves: Vec<(Vec<u8>, Vec<u8>)> = range(ZERO.clone(), pow(TWO.clone(), k))
        .map(|n| rightpad(&n.to_bytes_le(), B))
        .map(|u| (u.clone(), md(&u, &[])))
        .collect();

    let mut previous_level = Vec::new();
    let mut next_level = Vec::new();
    for x in leaves.chunks(2) {
        if let [ref a, ref b] = x {
            previous_level.append(&mut vec![
                ((a.0.clone(), a.0.clone()), a.1.clone()),
                ((b.0.clone(), b.0.clone()), b.1.clone())
            ]);
            next_level.push(pair_collisions(&a.1, &b.1, &md).unwrap());
        }
    }

    let mut tree = vec![previous_level, next_level.clone()];
    let mut previous_level = next_level.clone();

    while previous_level.len() >= 2 {
        let mut next_level = Vec::new();
        for x in previous_level.chunks(2) {
            if let [ref a, ref b] = x {
                next_level.push(pair_collisions(&a.1, &b.1, &md).unwrap());
            }
        }
        tree.push(next_level.clone());
        previous_level = next_level.clone();
    }

    (tree[tree.len()-1][0].1.clone(), tree)
}

pub fn forge_predicted_message(message: &[u8], len: usize, tree: &CollectionTree, md: HashFn) -> Vec<u8> {
    let message = rightpad(message, B);
    assert!(message.len() < len);

    let leaves: HashMap<Vec<u8>, usize> = tree.iter()
        .map(|r| r[0].clone())
        .enumerate()
        .map(|(i, l)| (l.1, i))
        .collect();

    let glue_len = len - message.len() - B * (tree.len() - 1);
    assert!(glue_len > 0);

    let (leaf_index, mut message) = range(
        pow(TWO.clone(), glue_len * 8 - 1),
        pow(TWO.clone(), glue_len * 8) - ONE.clone()
    )
        .rev()
        .map(|n| rightpad(&n.to_bytes_le(), B))
        .map(|u| [message.clone(), u].concat())
        .map(|b| (leaves.get(&md(&b, &[])), b))
        .find(|&(i, _)| i.is_some())
        .map(|(i, b)| (*i.unwrap(), b))
        .unwrap();

    assert_eq!(md(&message, &[]), tree[0][leaf_index].1);

    for i in 1..tree.len() {
        let leaf = tree[i][leaf_index / 2usize.pow(i as u32)].0.clone();
        let index = leaf_index / 2usize.pow(i as u32 - 1) % 2;

        message.append(&mut match index {
            0 => leaf.0,
            1 => leaf.1,
            _ => panic!()
        });
    };

    message
}


#[test]
fn it_works() {
    use iterated_hash_function_multicollisions::md_aes;

    let k = 4;
    let len = 128;
    let message = b"winner is china football.";
    let (hash, tree) = gen_predicted_hash(k, Box::new(md_aes));
    let forge_message = forge_predicted_message(message, len, &tree, Box::new(md_aes));

    assert!(forge_message.starts_with(message));
    assert_eq!(forge_message.len(), len);
    assert_eq!(md_aes(&forge_message, &[]), hash);
}

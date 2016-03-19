#![feature(question_mark)]

use std::fs::File;
use std::io::{ self, Read };
use std::hash::Hash;
use std::path::Path;
use std::collections::{ HashMap, HashSet };


pub type Dict = HashMap<usize, HashSet<String>>;
pub type Possible = HashMap<char, HashSet<char>>;
pub type Tablet = HashMap<char, char>;

pub fn read_dict<P: AsRef<Path>>(path: P) -> Result<Dict, io::Error> {
    let mut dict_string = String::new();
    let mut dict = Dict::new();

    File::open(path)?.read_to_string(&mut dict_string)?;
    for word in dict_string.lines().map(|r| r.to_lowercase()) {
        dict.entry(word.len())
            .or_insert(HashSet::new())
            .insert(word);
    }

    Ok(dict)
}

pub fn is_matching(origin: &str, word: &str) -> bool {
    fn wipe(word: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut tablet = HashMap::new();

        for c in word.chars() {
            let len = tablet.len();
            out.push(
                *tablet.entry(c)
                    .or_insert(len)
            );
        }

        out
    }

    wipe(origin) == wipe(word)
}

pub fn zip<T: Clone+Eq+Hash>(v: Vec<Vec<T>>) -> Vec<HashSet<T>> {
    let mut z = Vec::new();
    for i in 0..v.first().unwrap().len() {
        let mut zz = HashSet::new();
        for vv in &v {
            zz.insert(vv[i].clone());
        }
        z.push(zz);
    }
    z
}

pub fn replace(word: &str, tablet: Tablet) -> String {
    word.chars()
        .map(|c| tablet.get(&c).cloned().unwrap_or(c))
        .collect()
}

#[test]
fn test() {
    use std::char::from_u32;

    let dict = read_dict("/usr/share/dict/words").unwrap();
    let input = include_str!("input.txt");
    let output = include_str!("output.txt");
    let mut impossible = Possible::new();
    let alphabet: HashSet<char> = (b'a'..b'z'+1)
        .map(|r| from_u32(r as u32).unwrap())
        .collect();

    for (w, d) in input
        .split_whitespace()
        .map(|w| w. to_lowercase())
        .map(|w| (
            w.clone(),
            dict.get(&w.len()).unwrap_or(&HashSet::new()).clone()
        ))
        .map(|(w, d)| (
            w.clone(),
            d.iter()
                .filter(|&ww| is_matching(&w, ww))
                .cloned()
                .collect::<HashSet<String>>()
        ))
    {
        for (ww, zz) in w.chars().zip(zip(
            d.iter()
                .map(|s| s.chars().collect())
                .collect()
        ).iter())
        {
            let mut impossible_tablet = impossible.entry(ww)
                .or_insert(HashSet::new());
            for c in alphabet.difference(zz) {
                impossible_tablet.insert(*c);
            }
        }
    }

    let mut tablet = Tablet::new();

    let mut possible: Vec<(char, HashSet<char>)> = impossible.iter()
        .map(|(k, v)| (
            *k,
            alphabet.difference(v).cloned().collect()
        ))
        .collect();

    possible.sort_by(|&(_, ref x), &(_, ref y)| x.len().cmp(&y.len()));

    for (k, v) in possible {
        let impossible_set = tablet.values().cloned().collect();
        let possible_set = v.difference(&impossible_set).cloned().collect::<Vec<char>>();
        println!("{}: {:?}", k, possible_set);
        tablet.insert(
            k,
            if possible_set.len() == 1 {
                *possible_set.first().unwrap()
            } else {
                '?' // TODO check input search match.
            }
        );
    }

    assert_eq!(replace(input, tablet), output);
}

#![feature(question_mark)]

#[derive(Debug, PartialEq)]
pub enum UnPksc7Err {
    BadData,
    BadPadding
}

pub fn unpksc7padding(data: &[u8], len: usize) -> Result<Vec<u8>, UnPksc7Err> {
    if data.len() < len || data.len() % len != 0 { Err(UnPksc7Err::BadData)? }
    let &pad = data.last().unwrap();
    if pad as usize > len { Err(UnPksc7Err::BadPadding)? }
    let data_len = data.len() - (pad as usize);

    if data[data_len..].iter().all(|&r| r == pad) {
        Ok(data[..data_len].into())
    } else {
        Err(UnPksc7Err::BadPadding)
    }
}

#[test]
fn it_works() {
    assert_eq!(
        unpksc7padding(b"ICE ICE BABY\x04\x04\x04\x04", 16).ok(),
        Some("ICE ICE BABY".into())
    );
    assert_eq!(
        unpksc7padding(b"ICE ICE BABY\x05\x05\x05\x05", 16).err(),
        Some(UnPksc7Err::BadPadding)
    );
    assert_eq!(
        unpksc7padding(b"ICE ICE BABY\x01\x02\x03\x04", 16).err(),
        Some(UnPksc7Err::BadPadding)
    );
}

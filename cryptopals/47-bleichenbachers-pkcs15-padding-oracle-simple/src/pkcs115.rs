pub fn rand_nonzero_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| rand!(choose 1..(::std::u8::MAX) as usize+1) as u8)
        .collect()
}

pub fn padding(data: &[u8], len: usize) -> Vec<u8> {
    [
        vec![0x00, 0x02],
        rand_nonzero_bytes(len - data.len() - 3),
        vec![0x00],
        data.into()
    ].concat()
}

pub fn unpadding(data: &[u8], len: usize) -> Result<Vec<u8>, ()> {
    let data = leftpad!(data.to_vec(), len, 0x00);
    if data.len() != len || !data.starts_with(b"\x00\x02") { Err(())? };
    data[2..].iter()
        .position(|&n| n == 0x00)
        .map(|pos| data[pos+3..].into())
        .ok_or(())
}


#[test]
fn tset_rand_nonzero_bytes() {
    assert!(rand_nonzero_bytes(64).iter().all(|&n| n != 0x00));
}

#[test]
fn test_padding() {
    let data = rand!();
    assert_eq!(
        unpadding(&padding(&data, 64), 64).ok(),
        Some(data)
    );
}

#![feature(negate_unsigned)]

#[allow(dead_code)]
fn atoi(a: &str) -> Result<isize, ()> {
    let mut num = 0;
    let mut s = true;

    for i in 0..a.len() {
        if i == 0 && &a[i..i+1] == "+" || &a[i..i+1] == "-" {
            match &a[i..i+1] {
                "+" => (),
                "-" => {
                    s = false;
                },
                _ => {
                    return Err(());
                }
            };
        } else {
            num += (match &a[i..i+1] {
                "0" => 0,
                "1" => 1,
                "2" => 2,
                "3" => 3,
                "4" => 4,
                "5" => 5,
                "6" => 6,
                "7" => 7,
                "8" => 8,
                "9" => 9,
                _ => {
                    return Err(());
                }
            }) * 10isize.pow((a.len() - i - 1) as u32);
        };
    };

    Ok(if s {
        num
    } else {
        -num
    })
}

#[test]
fn it_works() {
    assert_eq!(atoi("12345").unwrap(), 12345);
    assert_eq!(atoi("+54321").unwrap(), 54321);
    assert_eq!(atoi("-54321").unwrap(), -54321);
    assert!(atoi("s4e21").is_err());
}

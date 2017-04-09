macro_rules! try {
    ( move : $exec:expr ) => {
        (move || Ok($exec))()
    };
    ( $exec:expr ) => {
        (|| Ok($exec))()
    }
}

#[test]
fn test() {
    match try!{ Err(())? } {
        Ok(()) => panic!(),
        Err(()) => ()
    }
}

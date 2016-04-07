#![feature(question_mark)]

macro_rules! try {
    ( $exec:expr ) => {
        (move || Ok($exec))()
    }
}

#[test]
fn test() {
    match try!{ Err(())? } {
        Ok(()) => panic!(),
        Err(()) => ()
    }
}

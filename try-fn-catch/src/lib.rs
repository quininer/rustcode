#![feature(question_mark)]

macro_rules! try_catch {
    ( $exec:expr ) => {
        (move || Ok($exec))()
    }
}

#[test]
fn test() {
    match try_catch!{ Err(())? } {
        Ok(()) => panic!(),
        Err(()) => ()
    }
}

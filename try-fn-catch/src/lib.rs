macro_rules! try_ {
    ( ref $( $token:tt )* ) => {{
        let b = || {
            $( $token )*
        };
        b()
    }};
    ( $( $token:tt )* ) => {{
        let b = move || {
            $( $token )*
        };
        b()
    }};
}

#[test]
fn test() {
    fn foo() -> std::io::Result<()> {
        Ok(())
    }

    match try_!{ Err(())? } {
        Ok(()) => panic!(),
        Err(()) => ()
    }
    
    let ret = try_!{
        let a = foo()?;
        Ok(a) as std::io::Result<()>
    };
    ret.unwrap();
}

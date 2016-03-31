use std::io;
use rustc_serialize::hex::ToHex;
use rouille::{ LogEntry, Request, Response, RouteError };
use super::hmac_sha1;

lazy_static!{
    static ref KEY: Vec<u8> = rand!(rand!(choose 5..40));
}

pub fn hmac_app(req: &Request) -> Response {
    LogEntry::start(io::stdout(), &req);

    router!( req,
        (GET) (/test/get) => {
            let file = b"foo";
            Ok(Response::json(&hashmap!{
                "file" => String::from_utf8(file.to_vec()).unwrap(),
                "signature" => hmac_sha1(&KEY, file).to_hex()
            }))
        },
        (GET) (/test/{file: String}/{signature: String}) => {
            Ok(Response::json(&hashmap!{
                "result" => hmac_sha1(&KEY, file.as_bytes()).to_hex()
                    ==
                    signature
            }))
        },
        _ => Err(RouteError::NoRouteFound)
    ).unwrap_or_else(|err| Response::from_error(&err))
}

#[macro_export]
macro_rules! request {
    ( $url:expr ) => {{
        let mut out = String::new();
        Client::new()
            .get($url)
            .header($crate::hyper::header::Connection::close())
            .send().unwrap()
            .read_to_string(&mut out).unwrap();
        decode(&out).unwrap()
    }}
}


#[test]
fn test_hmac_app() {
    use std::thread::spawn;
    use std::io::Read;
    use std::collections::HashMap;
    use rustc_serialize::json::decode;
    use rouille::start_server;
    use hyper::Client;

    spawn(|| start_server("127.0.0.1:8000", hmac_app));

    let result: HashMap<String, String> = request!("http://127.0.0.1:8000/test/get");
    assert_eq!(
        result.get("file"),
        Some(&String::from("foo"))
    );

    let result2: HashMap<String, bool> = request!(&format!(
        "http://127.0.0.1:8000/test/{}/{}",
        result.get("file").unwrap(),
        result.get("signature").unwrap()
    ));
    assert!(result2.get("result").unwrap());

    let result3: HashMap<String, bool> = request!(&format!(
        "http://127.0.0.1:8000/test/{}/{}",
        "wow",
        result.get("signature").unwrap()
    ));
    assert!(!result3.get("result").unwrap());
}

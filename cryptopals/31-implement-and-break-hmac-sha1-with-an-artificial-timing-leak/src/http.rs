use std::thread;
use std::time::Duration;
use rustc_serialize::hex::{ ToHex, FromHex };
use rouille::{ Request, Response, RouteError };
use super::hmac_sha1;

lazy_static!{
    static ref KEY: Vec<u8> = rand!(rand!(choose 5..40));
}
pub static mut INTERVAL: u64 = 50;

pub fn insecure_compare(hash: &[u8], signature: &[u8]) -> bool {
    println!(">> {} - {}", hash.to_hex(), signature.to_hex());
    if hash.len() != signature.len() || hash.len() == 0 {
        return false;
    }
    hash.iter().zip(signature.iter())
        .all(|(x, y)| {
            thread::sleep(Duration::from_millis(unsafe { INTERVAL }));
            x == y
        })
}

pub fn hmac_app(req: &Request) -> Response {
    router!( req,
        (GET) (/test/get) => {
            let file = b"foo";
            Ok(Response::json(&hashmap!{
                "file" => String::from_utf8(file.to_vec()).unwrap(),
                "signature" => hmac_sha1(&KEY, file).to_hex()
            }))
        },
        (GET) (/test/{file: String}/{signature: String}) => {
            Ok(if insecure_compare(
                &hmac_sha1(&KEY, file.as_bytes()),
                &signature.from_hex().unwrap()
            ) {
                Response::text("true").with_status_code(200)
            } else {
                Response::text("false").with_status_code(500)
            })
        },
        _ => Err(RouteError::NoRouteFound)
    ).unwrap_or_else(|err| Response::from_error(&err))
}

#[macro_export]
macro_rules! request {
    (request $url:expr ) => {
        $crate::hyper::Client::new()
            .get($url)
            .header($crate::hyper::header::Connection::close())
            .send().unwrap()
    };
    ( json $url:expr ) => {{
        use std::io::Read;
        let mut out = String::new();
        request!(request $url)
            .read_to_string(&mut out).unwrap();
        decode(&out).unwrap()
    }};
    ( $url:expr ) => {
        (request!(request $url)).status.is_success()
    }
}


#[test]
fn test_hmac_app() {
    use std::collections::HashMap;
    use rustc_serialize::json::decode;
    use rouille::start_server;

    thread::spawn(|| start_server("127.0.0.1:8000", hmac_app));

    let result: HashMap<String, String> = request!(json "http://127.0.0.1:8000/test/get");
    assert_eq!(result.get("file").unwrap(), "foo");

    assert!(request!(&format!(
        "http://127.0.0.1:8000/test/{}/{}",
        result.get("file").unwrap(),
        result.get("signature").unwrap()
    )));

    assert!(!request!(&format!(
        "http://127.0.0.1:8000/test/{}/{}",
        "wow",
        result.get("signature").unwrap()
    )));
}

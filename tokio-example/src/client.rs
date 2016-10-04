#[macro_use] extern crate futures;
#[macro_use] extern crate tokio_core;

use futures::Future;
use tokio_core::reactor::Core;
use tokio_core::net::TcpStream;
use tokio_core::io::{ write_all, read_exact };


fn main() {
    let addr = "127.0.0.1:8008".parse().unwrap();
    println!("addr: {}", addr);

    let mut lp = Core::new().unwrap();
    let handle = lp.handle();

    let done = TcpStream::connect(&addr, &handle)
        .and_then(|socket| write_all(socket, b"Hello world."))
        .and_then(|(socket, _)| read_exact(socket, [0; 12]))
        .map(|(_, buf)| println!("{}", String::from_utf8_lossy(&buf)))
        .map_err(|err| println!("error: {}", err));

    lp.run(done).unwrap();
}

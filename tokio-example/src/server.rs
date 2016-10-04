#[macro_use] extern crate futures;
#[macro_use] extern crate tokio_core;

use futures::Future;
use futures::stream::Stream;
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;
use tokio_core::io::{ Io, copy };


fn main() {
    let addr = "127.0.0.1:8008".parse().unwrap();
    println!("addr: {}", addr);

    let mut lp = Core::new().unwrap();
    let handle = lp.handle();

    let listener = TcpListener::bind(&addr, &handle).unwrap();

    let done = listener.incoming().for_each(move |(socket, addr)| {
        let done = futures::lazy(|| futures::finished(socket.split()))
            .and_then(|(reader, writer)| copy(reader, writer))
            .map(move |res| println!("{} bytes from {}", res, addr))
            .map_err(|err| println!("error: {}", err));
        handle.spawn(done);

        Ok(())
    });

    lp.run(done).unwrap();
}

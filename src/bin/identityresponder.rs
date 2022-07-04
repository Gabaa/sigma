use std::{io, net::TcpListener};

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("localhost:0")?;

    loop {
        let (stream, addr) = listener.accept()?;
    }
}

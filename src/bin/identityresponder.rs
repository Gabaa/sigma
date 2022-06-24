use std::{io, net::TcpListener};

use sigma::schnorr::SchnorrDiscreteLogProtocol;

fn main() -> io::Result<()> {
    let protocol = SchnorrDiscreteLogProtocol::new();

    let listener = TcpListener::bind("localhost:0")?;

    loop {
        let (stream, addr) = listener.accept()?;
    }
}

use std::{io, net::TcpListener};

use sigma::applications::commitments::{encode, CommitmentScheme};
use sigma::netutil::{read_value_from_stream, write_value_to_stream};

fn main() -> io::Result<()> {
    println!("Enter a value to commit to: ");
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;

    let encoded = encode(buf);

    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Listening for a connection on: {}", listener.local_addr()?);

    let (mut stream, addr) = listener.accept()?;
    println!("Received connection from: {}", addr);

    let instance = read_value_from_stream(&mut stream)?;
    let scheme = CommitmentScheme::new(instance);

    let (a, z) = scheme.commit(&encoded);
    write_value_to_stream(&mut stream, &a)?;

    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;

    write_value_to_stream(&mut stream, &(encoded, z))?;

    Ok(())
}

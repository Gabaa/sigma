use std::{io, net::TcpStream};

use sigma::applications::commitments::CommitmentScheme;
use sigma::netutil::{read_value_from_stream, write_value_to_stream};

fn main() -> io::Result<()> {
    println!("Creating instance...");
    let instance = CommitmentScheme::gen_params(2048, 256);

    println!("Enter the prover's socket address: ");
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let addr = buf.trim();

    let mut stream = TcpStream::connect(addr)?;

    write_value_to_stream(&mut stream, &instance)?;
    let scheme = CommitmentScheme::new(instance);

    let a = read_value_from_stream(&mut stream)?;
    let (e, z) = read_value_from_stream(&mut stream)?;

    assert!(scheme.verify(&a, &e, &z));

    Ok(())
}

use std::io;

use sigma::applications::commitments::encode;

fn main() {
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();

    let _encoded = encode(buf);
}

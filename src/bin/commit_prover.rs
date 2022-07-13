use std::io::stdin;

use num::BigInt;

struct CommitmentScheme {}

impl CommitmentScheme {
    fn new() -> Self {
        CommitmentScheme {}
    }

    fn commit(&mut self, value: BigInt) {
        todo!("{}", value)
    }

    fn open(&self) {
        todo!()
    }
}

fn main() {
    let mut scheme = CommitmentScheme::new();

    let mut buf = String::new();
    stdin().read_line(&mut buf).unwrap();

    let encoded = encode(buf);
    scheme.commit(encoded);
    scheme.open();
}

fn encode(s: String) -> BigInt {
    BigInt::from_signed_bytes_be(s.as_bytes())
}

fn decode(i: BigInt) -> String {
    String::from_utf8(i.to_signed_bytes_be()).unwrap()
}

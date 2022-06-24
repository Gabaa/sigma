use std::env;

use sigma::schnorr::SchnorrDiscreteLogProtocol;

fn main() {
    let args = env::args();
    let protocol = SchnorrDiscreteLogProtocol::new();
}

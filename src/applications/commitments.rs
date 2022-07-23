//! Create and verify commitments.

use num::{BigInt, BigUint};

use crate::schnorr::SchnorrDiscreteLogInstance;

#[derive(Debug)]
pub struct CommitmentScheme {
    instance: SchnorrDiscreteLogInstance,
}

impl CommitmentScheme {
    pub fn gen_params(p_size: usize, q_size: usize) -> (SchnorrDiscreteLogInstance, BigInt) {
        SchnorrDiscreteLogInstance::generate(p_size, q_size)
    }

    pub fn check_params(instance: SchnorrDiscreteLogInstance) -> bool {
        instance.is_valid()
    }

    pub fn commit(&self, value: BigUint) -> BigUint {
        todo!("{:?} {}", self.instance, value)
    }

    pub fn verify(&self, a: BigUint, e: BigUint, z: BigUint) -> bool {
        todo!("{self:?} {a} {e} {z}",)
    }
}

pub fn encode(s: String) -> BigUint {
    BigUint::from_bytes_be(s.as_bytes())
}

pub fn decode(i: BigUint) -> String {
    String::from_utf8(i.to_bytes_be()).unwrap()
}

#[cfg(test)]
mod tests {
    use num::BigInt;

    use crate::schnorr::SchnorrDiscreteLogInstance;

    use super::{decode, encode, CommitmentScheme};

    #[test]
    fn encode_decode_equals_identity() {
        let s = String::from("Hello, World!");
        assert_eq!(s, decode(encode(s.clone())));
    }

    #[test]
    fn generate_valid_params() {
        let (instance, _) = CommitmentScheme::gen_params(256, 32);
        assert!(CommitmentScheme::check_params(instance))
    }

    #[test]
    fn reject_invalid_params() {
        let instance = SchnorrDiscreteLogInstance::new(
            BigInt::from(1),
            BigInt::from(1),
            BigInt::from(1),
            BigInt::from(1),
        );
        assert!(!CommitmentScheme::check_params(instance))
    }

    #[test]
    fn accept_opened_commitment() {
        todo!()
    }

    #[test]
    fn reject_fake_commitment() {
        todo!()
    }
}

use std::fmt::Debug;

use crate::SigmaProtocol;

use num::{
    bigint::{BigInt, RandBigInt},
    integer::Integer,
    BigUint, One, Zero,
};
use num_primes::{Generator, Verification};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct SchnorrDiscreteLogInstance {
    p: BigInt,
    q: BigInt,
    g: BigInt,
    h: BigInt,
}

impl SchnorrDiscreteLogInstance {
    pub fn new(p: BigInt, q: BigInt, g: BigInt, h: BigInt) -> Self {
        SchnorrDiscreteLogInstance { p, q, g, h }
    }

    /// Generate a Schnorr protocol instance and a corresponding witness.
    ///
    /// We generate a [Schnorr group](https://crypto.stackexchange.com/questions/72811/the-definition-and-origin-of-schnorr-groups),
    /// choose a random `w`, and derive `h` from that.
    ///
    /// This implementation is very basic and could probably be greatly improved.
    pub fn generate(p_size: usize, q_size: usize) -> (Self, BigInt) {
        let q = Generator::new_prime(q_size);

        // Choose `r` randomly until `p := qr + 1` is a prime
        let mut rng = thread_rng();
        let (p, r) = loop {
            let r = rng.gen_biguint(p_size - q_size);
            let p = &q * &r + BigUint::one();
            if Verification::is_prime(&p) {
                break (p, r);
            }
        };

        // Choose h randomly until g := h^r !== 1 (mod p)
        let g = loop {
            let h = rng.gen_biguint_below(&p);
            let g = h.modpow(&r, &p);
            if g != BigUint::one() {
                break g;
            }
        };

        let w = rng.gen_biguint_below(&q);
        let h = g.modpow(&w, &p);

        (Self::new(p.into(), q.into(), g.into(), h.into()), w.into())
    }

    /// Check whether this instance is valid.
    pub fn is_valid(&self) -> bool {
        Verification::is_prime(&self.p.to_biguint().unwrap())
            && Verification::is_prime(&self.q.to_biguint().unwrap())
            && (&self.p - BigInt::from(1)).is_multiple_of(&self.q)
            && self.g < self.p
            && self.h < self.p
    }
}

impl Debug for SchnorrDiscreteLogInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "SchnorrDiscreteLogInstance {{ p: {:x}, q: {:x}, g: {:x}, h: {:x} }}",
            self.p, self.q, self.g, self.h,
        ))
    }
}

pub struct SchnorrDiscreteLogProtocol {
    instance: SchnorrDiscreteLogInstance,
    witness: Option<BigInt>,
    random_exponent: Option<BigInt>,
}

#[derive(Debug)]
pub enum SchnorrVerifierError {
    ExpressionsNotEqual { lhs: BigInt, rhs: BigInt },
}

impl SigmaProtocol<SchnorrDiscreteLogInstance, BigInt, BigInt, BigInt, BigInt>
    for SchnorrDiscreteLogProtocol
{
    type VerifierError = SchnorrVerifierError;

    fn new(instance: SchnorrDiscreteLogInstance, witness: Option<BigInt>) -> Self {
        SchnorrDiscreteLogProtocol {
            instance,
            witness,
            random_exponent: None,
        }
    }

    fn initial_message(&mut self) -> BigInt {
        let mut rng = rand::thread_rng();
        let r = rng.gen_bigint_range(&BigInt::from(0_i32), &self.instance.p);

        let a = self.instance.g.modpow(&r, &self.instance.p);

        self.random_exponent = Some(r);
        a
    }

    fn challenge(&mut self) -> BigInt {
        let t = BigInt::from(self.instance.q.bits() - 1);
        // TODO: Maybe check that this is valid
        let ubound = BigInt::from(2).modpow(&t, &self.instance.q);

        let mut rng = rand::thread_rng();
        rng.gen_bigint_range(&BigInt::from(0), &ubound)
    }

    fn challenge_response(&mut self, challenge: &BigInt) -> BigInt {
        let r = self
            .random_exponent
            .as_ref()
            .expect("Random exponent 'r' is not yet defined.");
        let w = self
            .witness
            .as_ref()
            .expect("Witness 'w' is not yet defined.");

        (r + challenge * w).modpow(&BigInt::from(1), &self.instance.q)
    }

    fn check(
        &mut self,
        initial_msg: BigInt,
        challenge: BigInt,
        response: BigInt,
    ) -> Result<(), Self::VerifierError> {
        let lhs = self.instance.g.modpow(&response, &self.instance.p);
        let rhs = (&initial_msg * self.instance.h.modpow(&challenge, &self.instance.p))
            .mod_floor(&self.instance.p);

        if lhs == rhs {
            Ok(())
        } else {
            Err(SchnorrVerifierError::ExpressionsNotEqual { lhs, rhs })
        }
    }

    fn simulate(&mut self, challenge: &BigInt) -> (BigInt, BigInt) {
        let p = &self.instance.p;

        let mut rng = rand::thread_rng();
        let z = rng.gen_bigint_range(&BigInt::zero(), p);

        // Calculate h^{-e} as (h^{-1})^{e}
        let h_inv = self.instance.h.extended_gcd(p).x;
        let h_pow_neg_e = h_inv.modpow(challenge, p);

        let g = &self.instance.g;
        let a = (g.modpow(&z, p) * h_pow_neg_e).mod_floor(&self.instance.p);

        (a, z)
    }
}

#[cfg(test)]
mod tests {
    use crate::SigmaProtocol;

    use super::{BigInt, SchnorrDiscreteLogInstance, SchnorrDiscreteLogProtocol};

    #[test]
    fn honest_run_is_accepted() {
        let p = BigInt::from(1907);
        let q = BigInt::from(953);
        let g = BigInt::from(343);
        let w = BigInt::from(121);

        let h = g.modpow(&w, &p);
        let instance = SchnorrDiscreteLogInstance { p, q, g, h };

        let mut protocol = SchnorrDiscreteLogProtocol::new(instance, Some(w));
        assert!(protocol.run_protocol().is_ok())
    }

    #[test]
    fn simulator_is_accepted() {
        let p = BigInt::from(1907);
        let q = BigInt::from(953);
        let g = BigInt::from(343);
        let h = BigInt::from(862);
        let instance = SchnorrDiscreteLogInstance { p, q, g, h };

        let e = BigInt::from(675);
        let mut protocol = SchnorrDiscreteLogProtocol::new(instance, None);
        let (a, z) = protocol.simulate(&e);

        assert!(protocol.check(a, e, z).is_ok())
    }

    #[test]
    fn generated_honest_run_is_accepted() {
        let (instance, w) = SchnorrDiscreteLogInstance::generate(256, 64);
        let mut protocol = SchnorrDiscreteLogProtocol::new(instance, Some(w));
        assert!(protocol.run_protocol().is_ok())
    }

    #[test]
    fn generated_simulator_is_accepted() {
        let (instance, _) = SchnorrDiscreteLogInstance::generate(256, 64);

        let e = BigInt::from(675);
        let mut protocol = SchnorrDiscreteLogProtocol::new(instance, None);
        let (a, z) = protocol.simulate(&e);

        assert!(protocol.check(a, e, z).is_ok())
    }
}

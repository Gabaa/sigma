use crate::SigmaProtocol;

use num::integer::Integer;
use num::{
    bigint::{BigInt, RandBigInt},
    Zero,
};

#[derive(Debug, Clone)]
pub struct SchnorrDiscreteLogInstance {
    p: BigInt,
    q: BigInt,
    g: BigInt,
    h: BigInt,
}

pub struct SchnorrDiscreteLogProtocol {
    instance: SchnorrDiscreteLogInstance,
    witness: Option<BigInt>,
    random_exponent: Option<BigInt>,
}

impl SigmaProtocol<SchnorrDiscreteLogInstance, BigInt, BigInt, BigInt, BigInt>
    for SchnorrDiscreteLogProtocol
{
    type VerifierError = ();

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

    fn challenge(&self) -> BigInt {
        let t = BigInt::from(self.instance.q.bits() - 1);
        // TODO: Maybe check that this is valid
        let ubound = BigInt::from(2).modpow(&t, &self.instance.q);

        let mut rng = rand::thread_rng();
        rng.gen_bigint_range(&BigInt::from(0), &ubound)
    }

    fn challenge_response(&self, challenge: &BigInt) -> BigInt {
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
        &self,
        initial_msg: BigInt,
        challenge: BigInt,
        response: BigInt,
    ) -> Result<(), Self::VerifierError> {
        let lhs = self.instance.g.modpow(&response, &self.instance.p);
        let rhs = (initial_msg * self.instance.h.modpow(&challenge, &self.instance.p))
            .modpow(&BigInt::from(1), &self.instance.p);

        if lhs == rhs {
            Ok(())
        } else {
            Err(())
        }
    }

    fn simulate(&self, challenge: &BigInt) -> (BigInt, BigInt) {
        let p = &self.instance.p;

        let mut rng = rand::thread_rng();
        let z = rng.gen_bigint_range(&BigInt::zero(), p);

        // Calculate h^{-e} as (h^{-1})^{e}
        let h_inv = self.instance.h.extended_gcd(p).x;
        let h_pow_neg_e = h_inv.modpow(challenge, p);

        let g = &self.instance.g;
        let a = g.modpow(&z, p) * h_pow_neg_e;

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
        let protocol = SchnorrDiscreteLogProtocol::new(instance, None);
        let (a, z) = protocol.simulate(&e);

        assert!(protocol.check(a, e, z).is_ok())
    }
}

use crate::{ProverProtocol, SigmaProtocol, Simulator, VerifierProtocol};

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

pub struct SchnorrDiscreteLogProtocol {}

impl SigmaProtocol<SchnorrProverProtocol, SchnorrVerifierProtocol, SchnorrSimulator>
    for SchnorrDiscreteLogProtocol
{
    type X = SchnorrDiscreteLogInstance;
    type W = BigInt;
    type A = BigInt;
    type E = BigInt;
    type Z = BigInt;
}

pub struct SchnorrProverProtocol {
    instance: SchnorrDiscreteLogInstance,
    witness: BigInt,
    random_exponent: Option<BigInt>,
}

impl ProverProtocol<SchnorrDiscreteLogInstance, BigInt, BigInt, BigInt, BigInt>
    for SchnorrProverProtocol
{
    fn new(instance: SchnorrDiscreteLogInstance, witness: BigInt) -> Self {
        SchnorrProverProtocol {
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

    fn challenge_response(self, challenge: BigInt) -> BigInt {
        let r = self
            .random_exponent
            .expect("Random exponent 'r' not yet defined.");

        (r + challenge * self.witness).modpow(&BigInt::from(1), &self.instance.q)
    }
}

pub struct SchnorrVerifierProtocol {
    instance: SchnorrDiscreteLogInstance,
}

impl VerifierProtocol<SchnorrDiscreteLogInstance, BigInt, BigInt, BigInt>
    for SchnorrVerifierProtocol
{
    type VerifierError = ();

    fn new(instance: SchnorrDiscreteLogInstance) -> Self {
        SchnorrVerifierProtocol { instance }
    }

    fn challenge(&self) -> BigInt {
        let t = BigInt::from(self.instance.q.bits() - 1);
        // TODO: Maybe check that this is valid
        let ubound = BigInt::from(2).modpow(&t, &self.instance.q);

        let mut rng = rand::thread_rng();
        rng.gen_bigint_range(&BigInt::from(0), &ubound)
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
}

pub struct SchnorrSimulator {}

impl Simulator<SchnorrDiscreteLogInstance, BigInt, BigInt, BigInt> for SchnorrSimulator {
    fn generate(
        &self,
        instance: SchnorrDiscreteLogInstance,
        challenge: BigInt,
    ) -> (BigInt, BigInt) {
        let mut rng = rand::thread_rng();
        let z = rng.gen_bigint_range(&BigInt::zero(), &instance.p);

        // Calculate h^{-e} as (h^{-1})^{e}
        let h_inv = instance.h.extended_gcd(&instance.p).x;
        let h_pow_neg_e = h_inv.modpow(&challenge, &instance.p);

        let a = instance.g.modpow(&z, &instance.p) * h_pow_neg_e;

        (a, z)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ProverProtocol, Simulator, VerifierProtocol};

    use super::{
        BigInt, SchnorrDiscreteLogInstance, SchnorrProverProtocol, SchnorrSimulator,
        SchnorrVerifierProtocol,
    };

    #[test]
    fn honest_run_is_accepted() {
        let p = BigInt::from(1907);
        let q = BigInt::from(953);
        let g = BigInt::from(343);
        let w = BigInt::from(121);

        let h = g.modpow(&w, &p);
        let instance = SchnorrDiscreteLogInstance { p, q, g, h };

        let mut prover = SchnorrProverProtocol::new(instance.clone(), w);
        let verifier = SchnorrVerifierProtocol::new(instance);

        let a = prover.initial_message();
        let e = verifier.challenge();
        let z = prover.challenge_response(e.clone());
        assert!(verifier.check(a, e, z).is_ok())
    }

    #[test]
    fn simulator_is_accepted() {
        let p = BigInt::from(1907);
        let q = BigInt::from(953);
        let g = BigInt::from(343);
        let h = BigInt::from(862);
        let instance = SchnorrDiscreteLogInstance { p, q, g, h };

        let sim = SchnorrSimulator {};
        let e = BigInt::from(675);
        let (a, z) = sim.generate(instance.clone(), e.clone());

        let verifier = SchnorrVerifierProtocol::new(instance);
        assert!(verifier.check(a, e, z).is_ok())
    }
}

use crate::{ProverProtocol, SigmaProtocol, VerifierProtocol};

use num_bigint::{BigInt, RandBigInt};

#[derive(Debug, Clone)]
pub struct SchnorrDiscreteLogInstance {
    p: BigInt,
    q: BigInt,
    g: BigInt,
    h: BigInt,
}

pub struct SchnorrDiscreteLogProtocol {}

impl SigmaProtocol<SchnorrProverProtocol, SchnorrVerifierProtocol> for SchnorrDiscreteLogProtocol {
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

#[cfg(test)]
mod tests {
    use crate::{ProverProtocol, VerifierProtocol};

    use super::{
        BigInt, SchnorrDiscreteLogInstance, SchnorrProverProtocol, SchnorrVerifierProtocol,
    };

    #[test]
    fn it_works() {
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
}

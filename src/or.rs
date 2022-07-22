use std::{fmt::Debug, ops::BitXor};

use crate::SigmaProtocol;

pub struct OrProtocol<P, E, Z> {
    protocols: (P, P),
    chosen_values: Option<(E, Z)>,
}

#[derive(Debug)]
pub enum OrProtocolVerifierError<VError> {
    SubProtocolError(VError),
    ChallengeXorNotEqual(String),
}

impl<P, X, W, A, E, Z> SigmaProtocol<(X, X), W, (A, A), E, (E, Z, E, Z)> for OrProtocol<P, E, Z>
where
    P: SigmaProtocol<X, W, A, E, Z>,
    E: BitXor<Output = E> + ToOwned<Owned = E> + PartialEq + Clone + Debug,
    Z: ToOwned<Owned = Z>,
{
    type VerifierError = OrProtocolVerifierError<P::VerifierError>;

    fn new(instance: (X, X), witness: Option<W>) -> Self {
        // TODO: Right now, we just assume that the first instance is the one matching the witness.
        OrProtocol {
            protocols: (P::new(instance.0, witness), P::new(instance.1, None)),
            chosen_values: None,
        }
    }

    fn initial_message(&mut self) -> (A, A) {
        // TODO: For security, order of real and simulated protocol should be random.
        let a0 = self.protocols.0.initial_message();
        let e1 = self.protocols.1.challenge();
        let (a1, z1) = self.protocols.1.simulate(&e1);

        self.chosen_values = Some((e1, z1));

        (a0, a1)
    }

    fn challenge(&mut self) -> E {
        self.protocols.0.challenge()
    }

    fn challenge_response(&mut self, challenge: &E) -> (E, Z, E, Z) {
        let (e1, z1) = self
            .chosen_values
            .as_ref()
            .expect("Chosen values 'e1' and 'z1' are not yet defined.")
            .to_owned();
        let e0 = challenge.to_owned() ^ e1.to_owned();
        let z0 = self.protocols.0.challenge_response(&e0);

        (e0, z0, e1.to_owned(), z1.to_owned())
    }

    fn check(
        &mut self,
        initial_msg: (A, A),
        challenge: E,
        response: (E, Z, E, Z),
    ) -> Result<(), Self::VerifierError> {
        let (a0, a1) = initial_msg;
        let (e0, z0, e1, z1) = response;

        let e = e0.clone() ^ e1.clone();
        if challenge != e {
            return Err(Self::VerifierError::ChallengeXorNotEqual(format!(
                "e0 = {:?}, e1 = {:?}, e = {:?}, challenge = {:?}",
                &e0, &e1, &e, &challenge
            )));
        }

        if let Err(err) = self.protocols.0.check(a0, e0, z0) {
            return Err(Self::VerifierError::SubProtocolError(err));
        }

        if let Err(err) = self.protocols.1.check(a1, e1, z1) {
            return Err(Self::VerifierError::SubProtocolError(err));
        }

        Ok(())
    }

    fn simulate(&mut self, challenge: &E) -> ((A, A), (E, Z, E, Z)) {
        let e0 = self.protocols.0.challenge();
        let e1 = challenge.clone() ^ e0.clone();
        let (a0, z0) = self.protocols.0.simulate(&e0);
        let (a1, z1) = self.protocols.1.simulate(&e1);

        ((a0, a1), (e0, z0, e1, z1))
    }
}

#[cfg(test)]
mod tests {
    use num::BigInt;

    use crate::{
        schnorr::{SchnorrDiscreteLogInstance, SchnorrDiscreteLogProtocol},
        SigmaProtocol,
    };

    use super::OrProtocol;

    type SchnorrOrProtocol = OrProtocol<SchnorrDiscreteLogProtocol, BigInt, BigInt>;

    fn make_instance() -> (
        (SchnorrDiscreteLogInstance, SchnorrDiscreteLogInstance),
        BigInt,
    ) {
        let p = BigInt::from(1907);
        let q = BigInt::from(953);
        let g = BigInt::from(343);

        let w = BigInt::from(121);
        let h1 = g.modpow(&w, &p);

        let h2 = BigInt::from(862);

        let instance = (
            SchnorrDiscreteLogInstance::new(p.clone(), q.clone(), g.clone(), h1),
            SchnorrDiscreteLogInstance::new(p, q, g, h2),
        );

        (instance, w)
    }

    #[test]
    fn honest_run_is_accepted() {
        let (instance, witness) = make_instance();
        let mut protocol = SchnorrOrProtocol::new(instance, Some(witness));
        let res = protocol.run_protocol();
        assert!(res.is_ok(), "Honest run not accepted: {:?}", res)
    }

    #[test]
    fn simulator_is_accepted() {
        let (instance, _) = make_instance();
        let mut protocol = SchnorrOrProtocol::new(instance, None);

        let e = BigInt::from(675);
        let (a, z) = protocol.simulate(&e);

        let res = protocol.check(a, e, z);
        assert!(res.is_ok(), "Simulator not accepted: {:?}", res)
    }
}

pub mod or;
pub mod schnorr;

pub trait SigmaProtocol<P, V, S>
where
    P: ProverProtocol<Self::X, Self::W, Self::A, Self::E, Self::Z>,
    V: VerifierProtocol<Self::X, Self::A, Self::E, Self::Z>,
    S: Simulator<Self::X, Self::A, Self::E, Self::Z>,
{
    type X;
    type W;
    type A;
    type E;
    type Z;
}

pub trait ProverProtocol<X, W, A, E, Z> {
    fn new(instance: X, witness: W) -> Self;
    fn initial_message(&mut self) -> A;
    fn challenge_response(self, challenge: E) -> Z;
}

pub trait VerifierProtocol<X, A, E, Z> {
    type VerifierError;

    fn new(instance: X) -> Self;
    fn challenge(&self) -> E;
    fn check(&self, initial_msg: A, challenge: E, response: Z) -> Result<(), Self::VerifierError>;
}

pub trait Simulator<X, A, E, Z> {
    fn generate(&self, instance: X, challenge: E) -> (A, Z);
}

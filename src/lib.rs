pub mod applications;
pub mod netutil;
pub mod or;
pub mod remote;
pub mod schnorr;

// TODO: Try to use immutable references for trait functions.
pub trait SigmaProtocol<X, W, A, E, Z> {
    type VerifierError;

    fn new(instance: X, witness: Option<W>) -> Self;
    fn initial_message(&mut self) -> A;
    fn challenge(&mut self) -> E;
    fn challenge_response(&mut self, challenge: &E) -> Z;
    fn check(
        &mut self,
        initial_msg: A,
        challenge: E,
        response: Z,
    ) -> Result<(), Self::VerifierError>;
    fn simulate(&mut self, challenge: &E) -> (A, Z);

    fn run_protocol(&mut self) -> Result<(), Self::VerifierError> {
        let a = self.initial_message();
        let e = self.challenge();
        let z = self.challenge_response(&e);
        self.check(a, e, z)
    }
}

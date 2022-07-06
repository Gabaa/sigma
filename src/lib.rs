pub mod or;
pub mod schnorr;

pub trait SigmaProtocol<X, W, A, E, Z> {
    type VerifierError;

    fn new(instance: X, witness: Option<W>) -> Self;
    fn initial_message(&mut self) -> A;
    fn challenge(&self) -> E;
    fn challenge_response(&self, challenge: &E) -> Z;
    fn check(&self, initial_msg: A, challenge: E, response: Z) -> Result<(), Self::VerifierError>;
    fn simulate(&self, challenge: &E) -> (A, Z);

    fn run_protocol(&mut self) -> Result<(), Self::VerifierError> {
        let a = self.initial_message();
        let e = self.challenge();
        let z = self.challenge_response(&e);
        self.check(a, e, z)
    }
}

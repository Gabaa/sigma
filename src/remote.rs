pub use remote_prover::{
    Protocol as RemoteProverProtocol, ProtocolError as RemoteProverProtocolError,
};
pub use remote_verifier::{
    Protocol as RemoteVerifierProtocol, ProtocolError as RemoteVerifierProtocolError,
};

mod remote_verifier {
    use std::io;

    use serde::Serialize;

    use crate::SigmaProtocol;

    pub struct Protocol<P> {
        protocol: P,
    }

    pub enum ProtocolError<VError> {
        SubProtocolError(VError),
        NetworkError(io::Error),
    }

    impl<P, X, W, A, E, Z> SigmaProtocol<X, W, A, E, Z> for Protocol<P>
    where
        P: SigmaProtocol<X, W, A, E, Z>,
        A: Serialize,
        E: Serialize,
        Z: Serialize,
    {
        type VerifierError = ProtocolError<P::VerifierError>;

        fn new(instance: X, witness: Option<W>) -> Self {
            Protocol {
                protocol: P::new(instance, witness),
            }
        }

        fn initial_message(&mut self) -> A {
            let a = self.protocol.initial_message();
            // TODO: Send to prover, need the address or stream (part of instance???)
            a
        }

        fn challenge(&self) -> E {
            // TODO
            todo!()
        }

        fn challenge_response(&self, challenge: &E) -> Z {
            // TODO
            todo!()
        }

        fn check(
            &self,
            initial_msg: A,
            challenge: E,
            response: Z,
        ) -> Result<(), Self::VerifierError> {
            // TODO
            todo!()
        }

        fn simulate(&self, challenge: &E) -> (A, Z) {
            // TODO
            todo!()
        }
    }
}

mod remote_prover {
    use std::io;

    use serde::Serialize;

    use crate::SigmaProtocol;

    pub struct Protocol<P> {
        protocol: P,
    }

    pub enum ProtocolError<VError> {
        SubProtocolError(VError),
        NetworkError(io::Error),
    }

    impl<P, X, W, A, E, Z> SigmaProtocol<X, W, A, E, Z> for Protocol<P>
    where
        P: SigmaProtocol<X, W, A, E, Z>,
        A: Serialize,
        E: Serialize,
        Z: Serialize,
    {
        type VerifierError = ProtocolError<P::VerifierError>;

        fn new(instance: X, _: Option<W>) -> Self {
            Protocol {
                protocol: P::new(instance, None),
            }
        }

        fn initial_message(&mut self) -> A {
            // TODO
            let a = self.protocol.initial_message();
            a
        }

        fn challenge(&self) -> E {
            // TODO
            todo!()
        }

        fn challenge_response(&self, challenge: &E) -> Z {
            // TODO
            todo!()
        }

        fn check(
            &self,
            initial_msg: A,
            challenge: E,
            response: Z,
        ) -> Result<(), Self::VerifierError> {
            // TODO
            todo!()
        }

        fn simulate(&self, challenge: &E) -> (A, Z) {
            // TODO
            todo!()
        }
    }
}

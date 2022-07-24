use std::net::TcpStream;

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    netutil::{read_value_from_stream, write_value_to_stream},
    SigmaProtocol,
};

pub struct RemoteVerifierProtocol<P> {
    protocol: P,
    stream: TcpStream,
}

#[derive(Debug)]
pub enum RemoteVerifierProtocolError<VError> {
    SubProtocolError(VError),
}

impl<P, X, W, A, E, Z> SigmaProtocol<(X, TcpStream), W, A, E, Z> for RemoteVerifierProtocol<P>
where
    P: SigmaProtocol<X, W, A, E, Z>,
    A: Serialize + DeserializeOwned,
    E: Serialize + DeserializeOwned,
    Z: Serialize + DeserializeOwned,
{
    // TODO: Would be nice if this was the actual error
    type VerifierError = ();

    fn new(instance: (X, TcpStream), witness: Option<W>) -> Self {
        // TODO: I don't like having the stream be part of the instance. Is there another way?
        RemoteVerifierProtocol {
            protocol: P::new(instance.0, witness),
            stream: instance.1,
        }
    }

    fn initial_message(&mut self) -> A {
        let a = self.protocol.initial_message();
        write_value_to_stream(&mut self.stream, &a).unwrap();
        a
    }

    fn challenge(&mut self) -> E {
        read_value_from_stream(&mut self.stream).unwrap()
    }

    fn challenge_response(&mut self, challenge: &E) -> Z {
        let z = self.protocol.challenge_response(challenge);
        write_value_to_stream(&mut self.stream, &z).unwrap();
        z
    }

    fn check(&mut self, _: A, _: E, _: Z) -> Result<(), Self::VerifierError> {
        let accepted: bool = read_value_from_stream(&mut self.stream).unwrap();
        if accepted {
            Ok(())
        } else {
            Err(())
        }
    }

    fn simulate(&mut self, challenge: &E) -> (A, Z) {
        self.protocol.simulate(challenge)
    }
}

pub struct RemoteProverProtocol<P> {
    protocol: P,
    stream: TcpStream,
}

#[derive(Debug)]
pub enum RemoteProverProtocolError<VError> {
    SubProtocolError(VError),
}

impl<P, X, W, A, E, Z> SigmaProtocol<(X, TcpStream), W, A, E, Z> for RemoteProverProtocol<P>
where
    P: SigmaProtocol<X, W, A, E, Z>,
    A: Serialize + DeserializeOwned,
    E: Serialize + DeserializeOwned,
    Z: Serialize + DeserializeOwned,
{
    type VerifierError = RemoteProverProtocolError<P::VerifierError>;

    fn new(instance: (X, TcpStream), _: Option<W>) -> Self {
        RemoteProverProtocol {
            protocol: P::new(instance.0, None),
            stream: instance.1,
        }
    }

    fn initial_message(&mut self) -> A {
        read_value_from_stream(&mut self.stream).unwrap()
    }

    fn challenge(&mut self) -> E {
        let e = self.protocol.challenge();
        write_value_to_stream(&mut self.stream, &e).unwrap();
        e
    }

    fn challenge_response(&mut self, _: &E) -> Z {
        read_value_from_stream(&mut self.stream).unwrap()
    }

    fn check(
        &mut self,
        initial_msg: A,
        challenge: E,
        response: Z,
    ) -> Result<(), Self::VerifierError> {
        let res = self
            .protocol
            .check(initial_msg, challenge, response)
            .map_err(RemoteProverProtocolError::SubProtocolError);
        write_value_to_stream(&mut self.stream, &res.is_ok()).unwrap();
        res
    }

    fn simulate(&mut self, challenge: &E) -> (A, Z) {
        self.protocol.simulate(challenge)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{TcpListener, TcpStream},
        thread,
    };

    use crate::{
        schnorr::{SchnorrDiscreteLogInstance, SchnorrDiscreteLogProtocol},
        SigmaProtocol,
    };

    use super::{RemoteProverProtocol, RemoteVerifierProtocol};

    fn perform_honest_run_in_threads(p_size: usize, q_size: usize) -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let listener_addr = listener.local_addr().unwrap();

        let (instance, witness) = SchnorrDiscreteLogInstance::generate(p_size, q_size);
        let instance_clone = instance.clone();

        // Start thread to handle listener/prover
        let prover_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut protocol: RemoteVerifierProtocol<SchnorrDiscreteLogProtocol> =
                RemoteVerifierProtocol::new((instance_clone, stream), Some(witness));

            protocol.run_protocol().unwrap();
        });

        // Start thread to handle verifier
        let verifier_handle = thread::spawn(move || {
            let stream = TcpStream::connect(listener_addr).unwrap();
            let mut protocol: RemoteProverProtocol<SchnorrDiscreteLogProtocol> =
                RemoteProverProtocol::new((instance, stream), None);

            protocol.run_protocol().unwrap();
        });

        prover_handle.join().unwrap();
        verifier_handle.join().unwrap();

        Ok(())
    }

    #[test]
    fn honest_run_works_locally() -> io::Result<()> {
        perform_honest_run_in_threads(2 << 8, 2 << 5)
    }

    #[test]
    #[ignore = "slow"]
    fn works_with_secure_params() -> io::Result<()> {
        perform_honest_run_in_threads(2 << 10, 2 << 7)
    }
}

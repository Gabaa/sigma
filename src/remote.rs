use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use serde::{de::DeserializeOwned, Serialize};

pub use remote_prover::{
    Protocol as RemoteProverProtocol, ProtocolError as RemoteProverProtocolError,
};
pub use remote_verifier::{
    Protocol as RemoteVerifierProtocol, ProtocolError as RemoteVerifierProtocolError,
};

fn read_value_from_stream<T: DeserializeOwned>(stream: &mut TcpStream) -> io::Result<T> {
    // Each value is prefixed by 4 bytes specifying the length.
    let mut buf = [0; 4];
    stream.read_exact(&mut buf)?;
    let length = u32::from_be_bytes(buf);

    let mut data = vec![0; length as usize];
    stream.read_exact(&mut data)?;
    let s = String::from_utf8(data).map_err(|r| io::Error::new(io::ErrorKind::InvalidData, r))?;

    let val: T = serde_json::from_str(&s)?;
    Ok(val)
}

fn write_value_to_stream<T: Serialize>(stream: &mut TcpStream, value: &T) -> io::Result<()> {
    let s = serde_json::to_string(value)?;
    let data = s.as_bytes();
    let length = data.len() as u32;

    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}

mod remote_verifier {
    use std::net::TcpStream;

    use serde::{de::DeserializeOwned, Serialize};

    use crate::SigmaProtocol;

    use super::{read_value_from_stream, write_value_to_stream};

    pub struct Protocol<P> {
        protocol: P,
        stream: TcpStream,
    }

    #[derive(Debug)]
    pub enum ProtocolError<VError> {
        SubProtocolError(VError),
    }

    impl<P, X, W, A, E, Z> SigmaProtocol<(X, TcpStream), W, A, E, Z> for Protocol<P>
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
            Protocol {
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
}

mod remote_prover {
    use std::net::TcpStream;

    use serde::{de::DeserializeOwned, Serialize};

    use crate::SigmaProtocol;

    use super::{read_value_from_stream, write_value_to_stream};

    pub struct Protocol<P> {
        protocol: P,
        stream: TcpStream,
    }

    #[derive(Debug)]
    pub enum ProtocolError<VError> {
        SubProtocolError(VError),
    }

    impl<P, X, W, A, E, Z> SigmaProtocol<(X, TcpStream), W, A, E, Z> for Protocol<P>
    where
        P: SigmaProtocol<X, W, A, E, Z>,
        A: Serialize + DeserializeOwned,
        E: Serialize + DeserializeOwned,
        Z: Serialize + DeserializeOwned,
    {
        type VerifierError = ProtocolError<P::VerifierError>;

        fn new(instance: (X, TcpStream), _: Option<W>) -> Self {
            Protocol {
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
                .map_err(ProtocolError::SubProtocolError);
            write_value_to_stream(&mut self.stream, &res.is_ok()).unwrap();
            res
        }

        fn simulate(&mut self, challenge: &E) -> (A, Z) {
            self.protocol.simulate(challenge)
        }
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

    #[test]
    fn honest_run_works_locally() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let listener_addr = listener.local_addr().unwrap();

        let (instance, witness) = SchnorrDiscreteLogInstance::generate(1024, 128);
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
}

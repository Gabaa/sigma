use crate::SigmaProtocol;

// pub struct OrProtocol<S, P, V>
// where
//     S: SigmaProtocol<P, V>,
//     P: ProverProtocol<
//         <S as SigmaProtocol<P, V>>::X,
//         <S as SigmaProtocol<P, V>>::W,
//         <S as SigmaProtocol<P, V>>::A,
//         <S as SigmaProtocol<P, V>>::E,
//         <S as SigmaProtocol<P, V>>::Z,
//     >,
//     V: VerifierProtocol<
//         <S as SigmaProtocol<P, V>>::X,
//         <S as SigmaProtocol<P, V>>::A,
//         <S as SigmaProtocol<P, V>>::E,
//         <S as SigmaProtocol<P, V>>::Z,
//     >;

pub struct OrProverProtocol<P, S> {
    b: u8,
    prover: P,
    simulator: S,
}

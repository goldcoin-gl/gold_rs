use crate::bytes::{Bytes, Bytes32};
use sha2::{Digest, Sha256};
use chia_bls::{G1Element, SecretKey};
use chia_streamable_macro::streamable;

#[streamable]
pub struct ProofOfSpace {
    challenge: Bytes32,
    pool_public_key: Option<G1Element>,
    pool_contract_puzzle_hash: Option<Bytes32>,
    local_public_key: G1Element,
    size: u8,
    proof: Bytes,
    farmer_public_key: G1Element,
}

impl ProofOfSpace {
    pub fn plot_public_key(&self) -> G1Element {
        let local_pk = &self.local_public_key;
        let farmer_pk = &self.farmer_public_key;
        let new_pk = local_pk + farmer_pk;
        if self.pool_contract_puzzle_hash.is_some() {
//             let taproot_message = [new_pk.to_bytes(), local_pk.to_bytes(), farmer_pk.to_bytes()].concat();
//             let hash = Sha256::digest(taproot_message);
//             let public_key = &SecretKey::from_seed(&hash).public_key();
//             return new_pk + public_key
            let mut hasher = Sha256::new();
            hasher.update(new_pk.to_bytes());
            hasher.update(local_pk.to_bytes());
            hasher.update(farmer_pk.to_bytes());
            let public_key = SecretKey::from_seed(&hasher.finalize()).public_key();
            return new_pk + &public_key;
        } else {
            return new_pk
        }
    }
}

#[cfg(feature = "py-bindings")]
use pyo3::prelude::*;

#[cfg(feature = "py-bindings")]
#[pymethods]
impl ProofOfSpace {
    #[getter]
    #[pyo3(name = "plot_public_key")]
    fn py_plot_public_key(&self) -> G1Element {
        self.plot_public_key()
    }
}
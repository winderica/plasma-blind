use ark_crypto_primitives::{
    Error,
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::iterable::Iterable;

use crate::datastructures::{nullifier::Nullifier, utxo::UTXOInfo};

use super::{TX_IO_SIZE, utxo::UTXO};

pub mod constraints;

#[derive(Clone, Debug)]
pub struct TransparentTransaction<F> {
    pub inputs: [UTXO<F>; TX_IO_SIZE],
    pub inputs_info: [UTXOInfo<F>; TX_IO_SIZE],
    pub outputs: [UTXO<F>; TX_IO_SIZE],
}

impl<F: Default + Copy> Default for TransparentTransaction<F> {
    fn default() -> Self {
        let inputs = [UTXO::default(); TX_IO_SIZE];
        let inputs_info = [UTXOInfo::default(); TX_IO_SIZE];
        let outputs = [UTXO::default(); TX_IO_SIZE];
        Self { inputs, inputs_info, outputs }
    }
}

impl<F: PrimeField + Absorb> TransparentTransaction<F> {
    pub fn set_input(&mut self, i: usize, utxo: UTXO<F>, info: UTXOInfo<F>) {
        self.inputs[i] = utxo;
        self.inputs_info[i] = info;
    }

    pub fn set_output(&mut self, i: usize, utxo: UTXO<F>) {
        self.outputs[i] = utxo;
    }
}

use ark_crypto_primitives::{
    Error,
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::iterable::Iterable;

use crate::datastructures::nullifier::Nullifier;

use super::{TX_IO_SIZE, utxo::UTXO};

pub mod constraints;

#[derive(Clone, Debug)]
pub struct TransparentTransaction<C: CurveGroup> {
    pub inputs: [UTXO<C>; TX_IO_SIZE],
    pub outputs: [UTXO<C>; TX_IO_SIZE],
}

impl<C: CurveGroup> Default for TransparentTransaction<C> {
    fn default() -> Self {
        let inputs = [UTXO::default(); TX_IO_SIZE];
        let mut outputs = [UTXO::default(); TX_IO_SIZE];
        for (i, utxo) in outputs.iter_mut().enumerate() {
            utxo.index = (TX_IO_SIZE + i) as u8;
        }
        Self { inputs, outputs }
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> TransparentTransaction<C> {
    pub fn new(inputs: [UTXO<C>; TX_IO_SIZE], outputs: [UTXO<C>; TX_IO_SIZE]) -> Self {
        Self { inputs, outputs }
    }

    pub fn get_default_output_utxos() -> [UTXO<C>; 4] {
        let mut output = [UTXO::<C>::default(); TX_IO_SIZE];
        let output_offset_index = TX_IO_SIZE / 2 - 1;
        for i in 0..TX_IO_SIZE {
            output[i].index = (i + output_offset_index) as u8;
        }
        output
    }

    pub fn utxos(&self) -> Vec<UTXO<C>> {
        [self.inputs, self.outputs].concat()
    }

    pub fn nullifiers(
        &self,
        pp: &PoseidonConfig<C::BaseField>,
        sk: &C::BaseField,
    ) -> Result<Vec<Nullifier<C::BaseField>>, Error> {
        self.inputs
            .iter()
            .map(|utxo| {
                Nullifier::new(
                    &pp,
                    *sk,
                    utxo.index,
                    utxo.tx_index.unwrap_or(0) as usize,
                    utxo.block_height.unwrap_or(0) as usize,
                )
            })
            .collect::<Result<Vec<Nullifier<C::BaseField>>, Error>>()
    }
}

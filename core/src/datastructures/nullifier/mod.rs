use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::{
    Error,
    crh::poseidon::CRH,
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;

pub mod constraints;

#[derive(Clone, Debug, Default)]
pub struct Nullifier<F> {
    value: F,
}

impl<F: PrimeField + Absorb> Nullifier<F> {
    pub fn new(
        cfg: &PoseidonConfig<F>,
        sk: F,
        utxo_idx: u8,
        tx_idx: usize,
        block_height: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            value: CRH::evaluate(
                cfg,
                [
                    sk,
                    F::from(utxo_idx),
                    F::from(tx_idx as u64),
                    F::from(block_height as u64),
                ],
            )?,
        })
    }
}

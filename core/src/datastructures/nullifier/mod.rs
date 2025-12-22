use std::marker::PhantomData;

use ark_crypto_primitives::{
    Error,
    crh::{
        CRHScheme,
        poseidon::{CRH, TwoToOneCRH},
    },
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use sonobe_primitives::traits::Inputize;

use crate::{NULLIFIER_TREE_HEIGHT, primitives::{crh::NullifierCRH, sparsemt::SparseConfig}};

pub mod constraints;

#[derive(Clone, Debug, Default)]
pub struct Nullifier<F> {
    pub value: F,
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

impl<F: PrimeField> Inputize<F> for Nullifier<F> {
    fn inputize(&self) -> Vec<F> {
        vec![self.value]
    }
}

#[derive(Clone, Debug, Default)]
pub struct NullifierTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for NullifierTreeConfig<F> {
    type Leaf = Nullifier<F>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    // the leaf hash is identity, since leaves are roots of mt
    type LeafHash = NullifierCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for NullifierTreeConfig<F> {
    const HEIGHT: usize = NULLIFIER_TREE_HEIGHT;
}

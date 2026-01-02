use std::marker::PhantomData;

use ark_crypto_primitives::{
    Error,
    crh::{
        CRHScheme,
        poseidon::TwoToOneCRH,
    },
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::{BigInteger, PrimeField};
use sonobe_primitives::{
    traits::Inputize,
    transcripts::{
        Absorbable,
        griffin::{GriffinParams, sponge::GriffinSponge},
    },
};

use crate::{
    NULLIFIER_TREE_HEIGHT,
    datastructures::utxo::UTXOInfo,
    primitives::{
        crh::IntervalCRH,
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

pub mod constraints;

#[derive(Clone, Debug, Default)]
pub struct Nullifier<F> {
    pub value: F,
}

impl<F: PrimeField + Absorb + Absorbable> Nullifier<F> {
    pub fn new(cfg: &GriffinParams<F>, sk: F, utxo_info: &UTXOInfo<F>) -> Result<Self, Error> {
        let digest = GriffinSponge::evaluate(
            cfg,
            [
                sk,
                F::from(utxo_info.utxo_index as u64),
                F::from(utxo_info.tx_index as u64),
                F::from(utxo_info.block_height as u64),
            ],
        )?;

        Ok(Self {
            value: F::from(F::BigInt::from_bits_le(
                &digest.into_bigint().to_bits_le()[1..F::MODULUS_BIT_SIZE as usize],
            )),
        })
    }
}

impl<F: PrimeField> Inputize<F> for Nullifier<F> {
    fn inputize(&self) -> Vec<F> {
        vec![self.value]
    }
}

pub type NullifierTree<F> = MerkleSparseTree<NullifierTreeConfig<F>>;

#[derive(Clone, Debug, Default)]
pub struct NullifierTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for NullifierTreeConfig<F> {
    type Leaf = (F, F);
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = IntervalCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for NullifierTreeConfig<F> {
    const HEIGHT: usize = NULLIFIER_TREE_HEIGHT;
}

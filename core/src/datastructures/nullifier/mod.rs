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
        crh::{IntervalCRH, NTo1CRH, utils::Init},
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

pub mod constraints;

#[derive(Clone, Debug, Default)]
pub struct Nullifier<F> {
    pub value: F,
}

impl<F: PrimeField + Absorb> Nullifier<F> {
    pub fn new<Cfg: Init<F = F>>(cfg: &Cfg, sk: F, utxo_info: &UTXOInfo<F>) -> Result<Self, Error> {
        let digest = Cfg::H::evaluate(
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

pub type NullifierTree<Cfg> = MerkleSparseTree<NullifierTreeConfig<Cfg>>;

#[derive(Clone, Debug, Default)]
pub struct NullifierTreeConfig<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init> Config for NullifierTreeConfig<Cfg> {
    type Leaf = (Cfg::F, Cfg::F);
    type LeafDigest = Cfg::F;
    type LeafInnerDigestConverter = IdentityDigestConverter<Cfg::F>;
    type InnerDigest = Cfg::F;
    type LeafHash = IntervalCRH<Cfg>;
    type TwoToOneHash = NTo1CRH<Cfg, 2>;
}

impl<Cfg: Init> SparseConfig for NullifierTreeConfig<Cfg> {
    const HEIGHT: usize = NULLIFIER_TREE_HEIGHT;
}

use std::marker::PhantomData;

use ark_crypto_primitives::{
    Error,
    crh::{CRHScheme, TwoToOneCRHScheme, poseidon::TwoToOneCRH},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use sonobe_primitives::transcripts::{Absorbable, griffin::GriffinParams};

use crate::{
    datastructures::{TX_IO_SIZE, nullifier::Nullifier},
    primitives::{
        crh::{IdentityCRH, NTo1CRH, UTXOCRH, utils::Init},
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

pub mod constraints;

use super::transparenttx::TransparentTransaction;

// Binary tree height to accommodate TX_IO_SIZE leaves.
// TX_IO_SIZE must be a power of 2.
pub const SHIELDED_TX_TREE_HEIGHT: usize = (TX_IO_SIZE.trailing_zeros() + 1) as usize;

// what's sent to the aggregator
#[derive(Clone, Debug)]
pub struct ShieldedTransaction<F> {
    pub input_nullifiers: Vec<Nullifier<F>>,
    pub output_utxo_commitments: Vec<F>,
}

impl<F: Absorb + PrimeField> ShieldedTransaction<F> {
    pub fn new<Cfg: Init<F = F>>(
        nullifier_hash_config: &Cfg,
        utxo_hash_config: &Cfg,
        sk: &F,
        transparent_tx: &TransparentTransaction<F>,
    ) -> Result<Self, Error> {
        Ok(Self {
            input_nullifiers: transparent_tx
                .inputs
                .iter()
                .zip(&transparent_tx.inputs_info)
                .map(|(utxo, info)| {
                    if utxo.is_dummy {
                        Ok(Nullifier { value: F::zero() })
                    } else {
                        Nullifier::new::<Cfg>(nullifier_hash_config, *sk, info)
                    }
                })
                .collect::<Result<_, _>>()?,
            output_utxo_commitments: transparent_tx
                .outputs
                .into_iter()
                .map(|i| {
                    if i.is_dummy {
                        Ok(F::zero())
                    } else {
                        UTXOCRH::<Cfg>::evaluate(utxo_hash_config, i)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl<F: Default + Clone> Default for ShieldedTransaction<F> {
    fn default() -> Self {
        Self {
            input_nullifiers: vec![Default::default(); TX_IO_SIZE],
            output_utxo_commitments: vec![Default::default(); TX_IO_SIZE],
        }
    }
}

pub type UTXOTree<Cfg> = MerkleSparseTree<ShieldedTransactionConfig<Cfg>>;

#[derive(Clone, Debug)]
pub struct ShieldedTransactionConfig<Cfg> {
    _cfg: PhantomData<Cfg>,
}

impl<Cfg: Init> Config for ShieldedTransactionConfig<Cfg> {
    type Leaf = Cfg::F;
    type LeafDigest = Cfg::F;
    type LeafInnerDigestConverter = IdentityDigestConverter<Cfg::F>;
    type InnerDigest = Cfg::F;
    type LeafHash = IdentityCRH<Cfg::F>;
    type TwoToOneHash = NTo1CRH<Cfg, 2>;
}

impl<Cfg: Init> SparseConfig for ShieldedTransactionConfig<Cfg> {
    const HEIGHT: usize = SHIELDED_TX_TREE_HEIGHT;
}

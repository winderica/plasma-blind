use std::marker::PhantomData;

use ark_crypto_primitives::{
    Error,
    crh::{CRHScheme, TwoToOneCRHScheme, poseidon::TwoToOneCRH},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;

use crate::{
    datastructures::{TX_IO_SIZE, nullifier::Nullifier},
    primitives::{
        crh::{IdentityCRH, UTXOCRH},
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

pub mod constraints;

use super::transparenttx::TransparentTransaction;

pub const SHIELDED_TX_TREE_HEIGHT: usize = 3; // 4 outputs

// what's sent to the aggregator
#[derive(Clone, Debug)]
pub struct ShieldedTransaction<F> {
    pub input_nullifiers: Vec<Nullifier<F>>,
    pub output_utxo_commitments: Vec<F>,
}

impl<F: Absorb + PrimeField> ShieldedTransaction<F> {
    pub fn new(
        nullifier_hash_config: &PoseidonConfig<F>,
        utxo_hash_config: &PoseidonConfig<F>,
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
                        Nullifier::new(nullifier_hash_config, *sk, info)
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
                        UTXOCRH::evaluate(utxo_hash_config, i)
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

pub type UTXOTree<F> = MerkleSparseTree<ShieldedTransactionConfig<F>>;

#[derive(Clone, Debug)]
pub struct ShieldedTransactionConfig<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for ShieldedTransactionConfig<F> {
    type Leaf = F;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = IdentityCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for ShieldedTransactionConfig<F> {
    const HEIGHT: usize = SHIELDED_TX_TREE_HEIGHT;
}

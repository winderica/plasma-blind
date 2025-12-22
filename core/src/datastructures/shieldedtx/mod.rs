use std::{collections::BTreeMap, marker::PhantomData};

use ark_crypto_primitives::{
    Error,
    crh::{CRHScheme, TwoToOneCRHScheme, poseidon::TwoToOneCRH},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::{
    datastructures::{TX_IO_SIZE, keypair::SecretKey, nullifier::Nullifier},
    primitives::{
        crh::{IdentityCRH, UTXOCRH},
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

pub mod constraints;

use super::{keypair::PublicKey, transparenttx::TransparentTransaction, utxo::UTXO};

pub const SHIELDED_TX_TREE_HEIGHT: usize = 3; // 4 outputs

// what's sent to the aggregator
#[derive(Clone, Debug)]
pub struct ShieldedTransaction<C: CurveGroup> {
    pub input_nullifiers: Vec<Nullifier<C::BaseField>>,
    pub output_utxo_commitments: Vec<C::BaseField>,
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>> ShieldedTransaction<C> {
    pub fn new(
        nullifier_hash_config: &PoseidonConfig<C::BaseField>,
        utxo_hash_config: &PoseidonConfig<C::BaseField>,
        sk: &C::BaseField,
        transparent_tx: &TransparentTransaction<C>,
    ) -> Result<Self, Error> {
        Ok((Self {
            input_nullifiers: transparent_tx.nullifiers(nullifier_hash_config, sk)?,
            output_utxo_commitments: transparent_tx
                .outputs()
                .into_iter()
                .map(|i| UTXOCRH::evaluate(utxo_hash_config, i))
                .collect::<Result<Vec<_>, _>>()?,
        }))
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Default for ShieldedTransaction<C> {
    fn default() -> Self {
        Self {
            input_nullifiers: vec![Default::default(); TX_IO_SIZE],
            output_utxo_commitments: vec![Default::default(); TX_IO_SIZE],
        }
    }
}

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

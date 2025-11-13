use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::primitives::{crh::UTXOCRH, sparsemt::SparseConfig};

pub mod constraints;

use super::utxo::UTXO;

pub type ShieldedTransaction<P> = MerkleTree<P>;

const SHIELDED_TX_TREE_HEIGHT: u64 = 3; // 4 inputs (resolving to 4 nullifiers) + 4 outputs

#[derive(Clone, Debug)]
pub struct ShieldedTransactionConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for ShieldedTransactionConfig<C> {
    type Leaf = UTXO<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = UTXOCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> SparseConfig for ShieldedTransactionConfig<C> {
    const HEIGHT: u64 = SHIELDED_TX_TREE_HEIGHT;
}

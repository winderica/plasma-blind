use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::{
    TX_TREE_HEIGHT,
    primitives::{
        crh::ShieldedTransactionCRH,
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

use super::shieldedtx::ShieldedTransaction;

pub mod constraints;

pub type TransactionTree<P> = MerkleSparseTree<P>;

#[derive(Clone, Debug)]
pub struct TransactionTreeConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for TransactionTreeConfig<C> {
    type Leaf = ShieldedTransaction<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    // the leaf hash is identity, since leaves are roots of mt
    type LeafHash = ShieldedTransactionCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> SparseConfig for TransactionTreeConfig<C> {
    const HEIGHT: u64 = TX_TREE_HEIGHT;
}

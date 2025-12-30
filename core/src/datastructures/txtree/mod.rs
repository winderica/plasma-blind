use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;

pub const TX_TREE_HEIGHT: usize = 12;
use crate::primitives::{
    crh::IdentityCRH,
    sparsemt::{MerkleSparseTree, SparseConfig},
};

pub mod constraints;

pub type TransactionTree<F> = MerkleSparseTree<TransactionTreeConfig<F>>;

#[derive(Clone, Debug, Default)]
pub struct TransactionTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for TransactionTreeConfig<F> {
    type Leaf = F;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    // the leaf hash is identity, since leaves are roots of mt
    type LeafHash = IdentityCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for TransactionTreeConfig<F> {
    const HEIGHT: usize = TX_TREE_HEIGHT;
}

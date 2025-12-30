use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::{CRH, TwoToOneCRH},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use nmerkle_trees::sparse::{NAryMerkleSparseTree, traits::NArySparseConfig};

pub const TX_TREE_HEIGHT: usize = 12;
use crate::primitives::{
    crh::IdentityCRH,
    sparsemt::{MerkleSparseTree, SparseConfig},
};

pub mod constraints;

pub type TransactionTree<F> = MerkleSparseTree<TransactionTreeConfig<F>>;

pub type SparseNAryTransactionTree<F> = NAryMerkleSparseTree<
    TRANSACTION_TREE_ARITY,
    TransactionTreeConfig<F>,
    SparseNAryTransactionTreeConfig<F>,
>;

pub const TRANSACTION_TREE_ARITY: usize = 7;
pub const NARY_TRANSACTION_TREE_HEIGHT: u64 = 5;

#[derive(Clone, Debug, Default)]
pub struct TransactionTreeConfig<F> {
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNAryTransactionTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField> NArySparseConfig<TRANSACTION_TREE_ARITY, TransactionTreeConfig<F>>
    for SparseNAryTransactionTreeConfig<F>
{
    type NToOneHashParams = PoseidonConfig<F>;
    type NToOneHash = CRH<F>;
    const HEIGHT: u64 = NARY_TRANSACTION_TREE_HEIGHT;
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

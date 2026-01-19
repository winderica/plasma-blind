use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use nmerkle_trees::sparse::{NAryMerkleSparseTree, traits::NArySparseConfig};
use sonobe_primitives::transcripts::{
    Absorbable,
    griffin::{GriffinParams, sponge::GriffinSponge},
};

use crate::primitives::{crh::IdentityCRH, sparsemt::MerkleSparseTree};

pub mod constraints;

pub type TransactionTree<F> = MerkleSparseTree<TransactionTreeConfig<F>>;

pub type SparseNAryTransactionTree<F> = NAryMerkleSparseTree<
    TRANSACTION_TREE_ARITY,
    TransactionTreeConfig<F>,
    SparseNAryTransactionTreeConfig<F>,
>;

pub const TRANSACTION_TREE_ARITY: usize = 4;
pub const NARY_TRANSACTION_TREE_HEIGHT: u64 = 7;

#[derive(Clone, Debug, Default)]
pub struct TransactionTreeConfig<F> {
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNAryTransactionTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField + Absorbable>
    NArySparseConfig<TransactionTreeConfig<F>>
    for SparseNAryTransactionTreeConfig<F>
{
    type NToOneHashParams = GriffinParams<F>;
    type NToOneHash = GriffinSponge<F>;
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

//impl<F: PrimeField + Absorb> SparseConfig for TransactionTreeConfig<F> {
//    const HEIGHT: usize = TX_TREE_HEIGHT;
//}

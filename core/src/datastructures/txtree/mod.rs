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

use crate::primitives::{crh::{IdentityCRH, NTo1CRH, utils::Init}, sparsemt::MerkleSparseTree};

pub mod constraints;

pub type TransactionTree<Cfg> = MerkleSparseTree<TransactionTreeConfig<Cfg>>;

pub type SparseNAryTransactionTree<Cfg> = NAryMerkleSparseTree<
    TRANSACTION_TREE_ARITY,
    TransactionTreeConfig<Cfg>,
    SparseNAryTransactionTreeConfig<Cfg>,
>;

pub const TRANSACTION_TREE_ARITY: usize = 4;
pub const NARY_TRANSACTION_TREE_HEIGHT: u64 = 7;

#[derive(Clone, Debug, Default)]
pub struct TransactionTreeConfig<Cfg> {
    _f: PhantomData<Cfg>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNAryTransactionTreeConfig<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init>
    NArySparseConfig<TransactionTreeConfig<Cfg>>
    for SparseNAryTransactionTreeConfig<Cfg>
{
    type NToOneHashParams = Cfg;
    type NToOneHash = Cfg::H;
    const HEIGHT: u64 = NARY_TRANSACTION_TREE_HEIGHT;
}

impl<Cfg: Init> Config for TransactionTreeConfig<Cfg> {
    type Leaf = Cfg::F;
    type LeafDigest = Cfg::F;
    type LeafInnerDigestConverter = IdentityDigestConverter<Cfg::F>;
    type InnerDigest = Cfg::F;
    // the leaf hash is identity, since leaves are roots of mt
    type LeafHash = IdentityCRH<Cfg::F>;
    type TwoToOneHash = NTo1CRH<Cfg, 2>;
}

//impl<F: PrimeField + Absorb> SparseConfig for TransactionTreeConfig<F> {
//    const HEIGHT: usize = TX_TREE_HEIGHT;
//}

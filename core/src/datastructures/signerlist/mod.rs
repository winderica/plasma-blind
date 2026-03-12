use std::marker::PhantomData;

use crate::primitives::{
    crh::{IdentityCRH, NTo1CRH, utils::Init},
    sparsemt::MerkleSparseTree,
};
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

use super::txtree::{NARY_TRANSACTION_TREE_HEIGHT, TRANSACTION_TREE_ARITY};

pub mod constraints;

pub type SignerList = Vec<u32>;
pub type SignerTree<F> = MerkleSparseTree<SignerTreeConfig<F>>;

pub type SparseNArySignerTree<F> =
    NAryMerkleSparseTree<SIGNER_TREE_ARITY, SignerTreeConfig<F>, SparseNArySignerTreeConfig<F>>;

//pub const SIGNER_TREE_HEIGHT: usize = super::txtree::TX_TREE_HEIGHT;
pub const SIGNER_TREE_ARITY: usize = TRANSACTION_TREE_ARITY;
pub const NARY_SIGNER_TREE_HEIGHT: u64 = NARY_TRANSACTION_TREE_HEIGHT;

#[derive(Clone, Debug, Default)]
pub struct SignerTreeConfig<Cfg> {
    _f: PhantomData<Cfg>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNArySignerTreeConfig<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init> NArySparseConfig<SignerTreeConfig<Cfg>>
    for SparseNArySignerTreeConfig<Cfg>
{
    type NToOneHashParams = Cfg;
    type NToOneHash = Cfg::H;
    const HEIGHT: u64 = NARY_SIGNER_TREE_HEIGHT;
}

impl<Cfg: Init> Config for SignerTreeConfig<Cfg> {
    type Leaf = Cfg::F;
    type LeafDigest = Cfg::F;
    type LeafInnerDigestConverter = IdentityDigestConverter<Cfg::F>;
    type InnerDigest = Cfg::F;
    type LeafHash = IdentityCRH<Cfg::F>;
    type TwoToOneHash = NTo1CRH<Cfg, 2>;
}

//impl<F: PrimeField + Absorb> SparseConfig for SignerTreeConfig<F> {
//    const HEIGHT: usize = SIGNER_TREE_HEIGHT;
//}

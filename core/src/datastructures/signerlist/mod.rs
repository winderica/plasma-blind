use std::marker::PhantomData;

use crate::primitives::{
    crh::IdentityCRH,
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
pub struct SignerTreeConfig<F> {
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNArySignerTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField + Absorbable> NArySparseConfig<SignerTreeConfig<F>>
    for SparseNArySignerTreeConfig<F>
{
    type NToOneHashParams = GriffinParams<F>;
    type NToOneHash = GriffinSponge<F>;
    const HEIGHT: u64 = NARY_SIGNER_TREE_HEIGHT;
}

impl<F: PrimeField + Absorb> Config for SignerTreeConfig<F> {
    type Leaf = F;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = IdentityCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

//impl<F: PrimeField + Absorb> SparseConfig for SignerTreeConfig<F> {
//    const HEIGHT: usize = SIGNER_TREE_HEIGHT;
//}

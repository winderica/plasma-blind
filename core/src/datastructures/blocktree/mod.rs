use ark_crypto_primitives::{
    crh::poseidon::{CRH, TwoToOneCRH},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use nmerkle_trees::sparse::NAryMerkleSparseTree;
use nmerkle_trees::sparse::traits::NArySparseConfig;
use std::marker::PhantomData;

use crate::{
    datastructures::block::BlockMetadata,
    primitives::{
        crh::BlockTreeCRH,
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

pub mod constraints;

pub type BlockTree<F> = MerkleSparseTree<BlockTreeConfig<F>>;
pub type SparseNAryBlockTree<F> =
    NAryMerkleSparseTree<BLOCK_TREE_ARITY, BlockTreeConfig<F>, SparseNAryBlockTreeConfig<F>>;

pub const BLOCK_TREE_HEIGHT: usize = 25;
pub const BLOCK_TREE_ARITY: usize = 3;
pub const NARY_BLOCK_TREE_HEIGHT: u64 = 14;

#[derive(Default, Clone, Debug)]
pub struct BlockTreeConfig<F> {
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNAryBlockTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField> NArySparseConfig<BLOCK_TREE_ARITY, BlockTreeConfig<F>>
    for SparseNAryBlockTreeConfig<F>
{
    type NToOneHashParams = PoseidonConfig<F>;
    type NToOneHash = CRH<F>;
    const HEIGHT: u64 = NARY_BLOCK_TREE_HEIGHT;
}

impl<F: Absorb + PrimeField> Config for BlockTreeConfig<F> {
    type Leaf = BlockMetadata<F>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = BlockTreeCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: Absorb + PrimeField> SparseConfig for BlockTreeConfig<F> {
    const HEIGHT: usize = BLOCK_TREE_HEIGHT;
}

use ark_crypto_primitives::{
    crh::poseidon::{CRH, TwoToOneCRH},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use nmerkle_trees::sparse::NAryMerkleSparseTree;
use nmerkle_trees::sparse::traits::NArySparseConfig;
use sonobe_primitives::transcripts::{
    Absorbable,
    griffin::{GriffinParams, sponge::GriffinSponge},
};
use std::marker::PhantomData;

use crate::{
    datastructures::block::BlockMetadata,
    primitives::{
        crh::{BlockTreeCRH, BlockTreeCRHGriffin},
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};

pub mod constraints;

pub type BlockTree<F> = MerkleSparseTree<BlockTreeConfig<F>>;
pub type SparseNAryBlockTree<F> =
    NAryMerkleSparseTree<BLOCK_TREE_ARITY, BlockTreeConfig<F>, SparseNAryBlockTreeConfig<F>>;

// pub const BLOCK_TREE_HEIGHT: usize = 25;
pub const BLOCK_TREE_ARITY: usize = 4;
pub const NARY_BLOCK_TREE_HEIGHT: u64 = 6;

#[derive(Default, Clone, Debug)]
pub struct BlockTreeConfig<F> {
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNAryBlockTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField + Absorbable> NArySparseConfig<BLOCK_TREE_ARITY, BlockTreeConfig<F>>
    for SparseNAryBlockTreeConfig<F>
{
    type NToOneHashParams = GriffinParams<F>;
    type NToOneHash = GriffinSponge<F>;
    const HEIGHT: u64 = NARY_BLOCK_TREE_HEIGHT;
}

impl<F: Absorb + PrimeField + Absorbable> Config for BlockTreeConfig<F> {
    type Leaf = BlockMetadata<F>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = BlockTreeCRHGriffin<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

//impl<F: Absorb + PrimeField + Absorbable> SparseConfig for BlockTreeConfig<F> {
//    const HEIGHT: usize = BLOCK_TREE_HEIGHT;
//}

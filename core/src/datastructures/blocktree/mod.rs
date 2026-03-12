use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
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
        crh::{BlockTreeCRH, NTo1CRH, utils::Init}, sparsemt::MerkleSparseTree
    },
};

pub mod constraints;

pub type BlockTree<F> = MerkleSparseTree<BlockTreeConfig<F>>;
pub type SparseNAryBlockTree<F> =
    NAryMerkleSparseTree<BLOCK_TREE_ARITY, BlockTreeConfig<F>, SparseNAryBlockTreeConfig<F>>;

// pub const BLOCK_TREE_HEIGHT: usize = 25;
pub const BLOCK_TREE_ARITY: usize = 4;
pub const NARY_BLOCK_TREE_HEIGHT: u64 = match option_env!("BLOCK_TREE_HEIGHT") {
    Some(s) => {
        let bytes = s.as_bytes();
        let mut result: u64 = 0;
        let mut i = 0;
        while i < bytes.len() {
            result = result * 10 + (bytes[i] - b'0') as u64;
            i += 1;
        }
        result
    }
    None => 6,
};

#[derive(Default, Clone, Debug)]
pub struct BlockTreeConfig<Cfg> {
    _f: PhantomData<Cfg>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNAryBlockTreeConfig<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init> NArySparseConfig<BlockTreeConfig<Cfg>>
    for SparseNAryBlockTreeConfig<Cfg>
{
    type NToOneHashParams = Cfg;
    type NToOneHash = Cfg::H;
    const HEIGHT: u64 = NARY_BLOCK_TREE_HEIGHT;
}

impl<Cfg: Init> Config for BlockTreeConfig<Cfg> {
    type Leaf = BlockMetadata<Cfg::F>;
    type LeafDigest = Cfg::F;
    type LeafInnerDigestConverter = IdentityDigestConverter<Cfg::F>;
    type InnerDigest = Cfg::F;
    type LeafHash = BlockTreeCRH<Cfg>;
    type TwoToOneHash = NTo1CRH<Cfg, 2>;
}

//impl<F: Absorb + PrimeField + Absorbable> SparseConfig for BlockTreeConfig<F> {
//    const HEIGHT: usize = BLOCK_TREE_HEIGHT;
//}

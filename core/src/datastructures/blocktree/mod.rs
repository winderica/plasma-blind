use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use std::marker::PhantomData;

use crate::primitives::{
    crh::BlockTreeCRH,
    sparsemt::{MerkleSparseTree, SparseConfig},
};

use super::block::BlockHash;

pub mod constraints;

pub type BlockTree<P> = MerkleSparseTree<P>;

pub const BLOCK_TREE_HEIGHT: usize = 25;

#[derive(Clone, Debug)]
pub struct BlockTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField> Config for BlockTreeConfig<F> {
    type Leaf = BlockHash<F>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = BlockTreeCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: Absorb + PrimeField> SparseConfig for BlockTreeConfig<F> {
    const HEIGHT: usize = BLOCK_TREE_HEIGHT;
}

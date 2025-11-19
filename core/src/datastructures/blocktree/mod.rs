use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use std::marker::PhantomData;

use crate::primitives::{crh::BlockTreeCRH, sparsemt::SparseConfig};

use super::block::BlockHash;

pub mod constraints;

const BLOCK_TREE_HEIGHT: u64 = 25;

#[derive(Clone, Debug)]
pub struct BlockTreeConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>> Config for BlockTreeConfig<C> {
    type Leaf = BlockHash<C::BaseField>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = BlockTreeCRH<C::BaseField>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>> SparseConfig for BlockTreeConfig<C> {
    const HEIGHT: u64 = BLOCK_TREE_HEIGHT;
}

use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

use super::{BLOCK_TREE_HEIGHT, BlockTreeConfig};
use crate::{
    datastructures::block::constraints::BlockMetadataVar, primitives::{
        crh::constraints::BlockTreeVarCRH,
        sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
    }
};

pub type BlockTreeGadget<F> =
    MerkleSparseTreeGadget<BlockTreeConfig<F>, F, BlockTreeConfigGadget<F>>;

pub struct BlockTreeConfigGadget<F: Absorb + PrimeField> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField> ConfigGadget<BlockTreeConfig<F>, F> for BlockTreeConfigGadget<F> {
    type Leaf = BlockMetadataVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = BlockTreeVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: Absorb + PrimeField> SparseConfigGadget<BlockTreeConfig<F>, F>
    for BlockTreeConfigGadget<F>
{
    const HEIGHT: usize = BLOCK_TREE_HEIGHT;
}

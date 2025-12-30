use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::{CRHGadget, TwoToOneCRHGadget},
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use nmerkle_trees::sparse::traits::NArySparseConfigGadget;

use super::{
    BLOCK_TREE_ARITY, BLOCK_TREE_HEIGHT, BlockTreeConfig, NARY_BLOCK_TREE_HEIGHT,
    SparseNAryBlockTreeConfig,
};
use crate::{
    datastructures::block::constraints::BlockMetadataVar,
    primitives::{
        crh::constraints::BlockTreeVarCRH,
        sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
    },
};

pub type BlockTreeGadget<F> =
    MerkleSparseTreeGadget<BlockTreeConfig<F>, F, BlockTreeConfigGadget<F>>;

pub struct SparseNAryBlockTreeConfigGadget<F: Absorb + PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb>
    NArySparseConfigGadget<
        BLOCK_TREE_ARITY,
        BlockTreeConfig<F>,
        BlockTreeConfigGadget<F>,
        F,
        SparseNAryBlockTreeConfig<F>,
    > for SparseNAryBlockTreeConfigGadget<F>
{
    const HEIGHT: u64 = NARY_BLOCK_TREE_HEIGHT;
    type NToOneHash = CRHGadget<F>;
}

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

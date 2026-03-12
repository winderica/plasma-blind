use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use nmerkle_trees::sparse::traits::NArySparseConfigGadget;
use sonobe_primitives::transcripts::{Absorbable, griffin::sponge::GriffinSpongeVar};

use super::{BLOCK_TREE_ARITY, BlockTreeConfig, NARY_BLOCK_TREE_HEIGHT, SparseNAryBlockTreeConfig};
use crate::{
    datastructures::block::constraints::BlockMetadataVar,
    primitives::{
        crh::{
            constraints::{BlockTreeVarCRH, NTo1CRHVar},
            utils::Init,
        },
        sparsemt::constraints::MerkleSparseTreeGadget,
    },
};

pub type BlockTreeGadget<F> =
    MerkleSparseTreeGadget<BlockTreeConfig<F>, F, BlockTreeConfigGadget<F>>;

pub struct SparseNAryBlockTreeConfigGadget<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init>
    NArySparseConfigGadget<
        BlockTreeConfig<Cfg>,
        BlockTreeConfigGadget<Cfg>,
        Cfg::F,
        SparseNAryBlockTreeConfig<Cfg>,
    > for SparseNAryBlockTreeConfigGadget<Cfg>
{
    const HEIGHT: u64 = NARY_BLOCK_TREE_HEIGHT;
    type NToOneHash = Cfg::HGadget;
}

pub struct BlockTreeConfigGadget<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init> ConfigGadget<BlockTreeConfig<Cfg>, Cfg::F> for BlockTreeConfigGadget<Cfg> {
    type Leaf = BlockMetadataVar<Cfg::F>;
    type LeafDigest = FpVar<Cfg::F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<Cfg::F>>;
    type InnerDigest = FpVar<Cfg::F>;
    type LeafHash = BlockTreeVarCRH<Cfg>;
    type TwoToOneHash = NTo1CRHVar<Cfg, 2>;
}

//impl<F: Absorb + PrimeField + Absorbable> SparseConfigGadget<BlockTreeConfig<F>, F>
//    for BlockTreeConfigGadget<F>
//{
//    const HEIGHT: usize = BLOCK_TREE_HEIGHT;
//}

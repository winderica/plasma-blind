use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

use crate::{
    datastructures::block::constraints::BlockHashVar,
    primitives::{crh::constraints::BlockTreeVarCRH, sparsemt::constraints::SparseConfigGadget},
};

use super::{BLOCK_TREE_HEIGHT, BlockTreeConfig};

pub struct BlockTreeConfigGadget<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    _c: PhantomData<C>,
    _c1: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    ConfigGadget<BlockTreeConfig<C>, C::BaseField> for BlockTreeConfigGadget<C, CVar>
{
    type Leaf = BlockHashVar<C::BaseField>;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = BlockTreeVarCRH<C::BaseField>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    SparseConfigGadget<BlockTreeConfig<C>, C::BaseField> for BlockTreeConfigGadget<C, CVar>
{
    const HEIGHT: u64 = BLOCK_TREE_HEIGHT;
}

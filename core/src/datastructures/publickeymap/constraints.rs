use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

use crate::{
    datastructures::keypair::constraints::PublicKeyVar,
    primitives::crh::{constraints::{NTo1CRHVar, PublicKeyVarCRH}, utils::Init},
};

use super::PublicKeyTreeConfig;

pub struct PublicKeyTreeConfigGadget<
    Cfg,
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    _c: PhantomData<(Cfg, C, CVar)>,
}

impl<Cfg: Init, C: CurveGroup<BaseField = Cfg::F>, CVar: CurveVar<C, C::BaseField>>
    ConfigGadget<PublicKeyTreeConfig<Cfg, C>, C::BaseField> for PublicKeyTreeConfigGadget<Cfg, C, CVar>
{
    type Leaf = PublicKeyVar<C, CVar>;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = PublicKeyVarCRH<Cfg, C, CVar>;
    type TwoToOneHash = NTo1CRHVar<Cfg, 2>;
}

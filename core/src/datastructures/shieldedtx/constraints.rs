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
    datastructures::utxo::constraints::UTXOVar,
    primitives::{crh::constraints::UTXOVarCRH, sparsemt::constraints::SparseConfigGadget},
};

use super::{SHIELDED_TX_TREE_HEIGHT, ShieldedTransactionConfig};

pub type ShieldedTransactionVar<C, CVar> = ShieldedTransactionConfigGadget<C, CVar>;

#[derive(Clone, Debug)]
pub struct ShieldedTransactionConfigGadget<C, CVar> {
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField>, CVar: CurveVar<C, C::BaseField>>
    ConfigGadget<ShieldedTransactionConfig<C>, C::BaseField>
    for ShieldedTransactionConfigGadget<C, CVar>
where
    C::BaseField: Absorb,
{
    type Leaf = UTXOVar<C, CVar>;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = UTXOVarCRH<C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    SparseConfigGadget<ShieldedTransactionConfig<C>, C::BaseField>
    for ShieldedTransactionConfigGadget<C, CVar>
{
    const HEIGHT: u64 = SHIELDED_TX_TREE_HEIGHT;
}

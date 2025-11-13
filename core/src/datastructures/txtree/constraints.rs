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
    TX_TREE_HEIGHT,
    datastructures::shieldedtx::{
        ShieldedTransactionConfig, constraints::ShieldedTransactionConfigGadget,
    },
    primitives::{
        crh::constraints::ShieldedTransactionVarCRH, sparsemt::constraints::SparseConfigGadget,
    },
};

use super::TransactionTreeConfig;

#[derive(Clone, Debug)]
pub struct TransactionTreeConfigGadget<C, CVar> {
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    ConfigGadget<TransactionTreeConfig<C>, C::BaseField> for TransactionTreeConfigGadget<C, CVar>
{
    // leaves are shielded transactions (i.e. roots of a mt)
    type Leaf = <ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::InnerDigest;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    // the leaf hash is identity, since leaves are roots of mt
    type LeafHash = ShieldedTransactionVarCRH<C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    SparseConfigGadget<TransactionTreeConfig<C>, C::BaseField>
    for TransactionTreeConfigGadget<C, CVar>
{
    const HEIGHT: u64 = TX_TREE_HEIGHT;
}

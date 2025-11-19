use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar};

use crate::{
    datastructures::{keypair::constraints::PublicKeyVar, utxo::constraints::UTXOVar},
    primitives::crh::constraints::UTXOVarCRH,
};

use super::{ShieldedTransaction, ShieldedTransactionConfig};

#[derive(Clone, Debug)]
pub struct ShieldedTransactionVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    pub from: PublicKeyVar<C, CVar>,
    pub shielded_tx: <ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::InnerDigest,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<ShieldedTransaction<C>, C::BaseField> for ShieldedTransactionVar<C, CVar>
{
    fn new_variable<T: std::borrow::Borrow<ShieldedTransaction<C>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let res = f()?;
        let tx: &ShieldedTransaction<C> = res.borrow();
        let from = PublicKeyVar::new_variable(cs.clone(), || Ok(tx.from), mode)?;
        let shielded_tx = FpVar::new_variable(cs.clone(), || Ok(tx.shielded_tx), mode)?;
        Ok(ShieldedTransactionVar { from, shielded_tx })
    }
}

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

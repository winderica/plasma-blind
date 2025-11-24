use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    groups::CurveVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};

use super::{UTXO, UTXOTreeConfig};
use crate::{
    datastructures::keypair::constraints::PublicKeyVar,
    primitives::{crh::constraints::UTXOVarCRH, sparsemt::constraints::SparseConfigGadget},
};

#[derive(Clone, Debug)]
pub struct UTXOVar<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>> {
    pub amount: FpVar<C::BaseField>,
    pub pk: PublicKeyVar<C, CVar>,
    pub salt: FpVar<C::BaseField>,
    pub is_dummy: Boolean<C::BaseField>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<UTXO<C>, C::BaseField> for UTXOVar<C, CVar>
{
    fn new_variable<T: Borrow<UTXO<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let UTXO {
            salt,
            amount,
            pk,
            is_dummy,
        } = f.borrow();
        Ok(Self {
            amount: FpVar::new_variable(cs.clone(), || Ok(C::BaseField::from(*amount)), mode)?,
            pk: PublicKeyVar::new_variable(cs.clone(), || Ok(*pk), mode)?,
            salt: FpVar::new_variable(cs.clone(), || Ok(C::BaseField::from(*salt)), mode)?,
            is_dummy: Boolean::new_variable(cs, || Ok(is_dummy), mode)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct UTXOTreeConfigGadget<C, CVar> {
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    ConfigGadget<UTXOTreeConfig<C>, C::BaseField> for UTXOTreeConfigGadget<C, CVar>
{
    type Leaf = UTXOVar<C, CVar>;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = UTXOVarCRH<C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    SparseConfigGadget<UTXOTreeConfig<C>, C::BaseField> for UTXOTreeConfigGadget<C, CVar>
{
    const HEIGHT: u64 = 32;
}

use std::borrow::Borrow;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    groups::CurveVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::datastructures::{
    TX_IO_SIZE,
    keypair::{PublicKey, constraints::PublicKeyVar},
    utxo::constraints::UTXOVar,
};

use super::TransparentTransaction;

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    TryInto<Vec<FpVar<C::BaseField>>> for &TransparentTransactionVar<C, CVar>
{
    type Error = SynthesisError;
    fn try_into(self) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError> {
        let mut arr = Vec::new();
        for utxo in self.inputs.iter().chain(&self.outputs) {
            arr.push(utxo.amount.clone());
            arr.push(utxo.is_dummy.clone().into());
            let point = utxo.pk.key.to_constraint_field()?;
            for p in point {
                arr.push(p);
            }
        }
        Ok(arr)
    }
}

#[derive(Clone, Debug)]
pub struct TransparentTransactionVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    pub inputs: [UTXOVar<C, CVar>; TX_IO_SIZE],
    pub outputs: [UTXOVar<C, CVar>; TX_IO_SIZE],
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<TransparentTransaction<C>, C::BaseField> for TransparentTransactionVar<C, CVar>
{
    fn new_variable<T: Borrow<TransparentTransaction<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let TransparentTransaction { inputs, outputs } = f.borrow();
        Ok(Self {
            inputs: Vec::new_variable(cs.clone(), || Ok(&inputs[..]), mode)?
                .try_into()
                .unwrap(),
            outputs: Vec::new_variable(cs.clone(), || Ok(&outputs[..]), mode)?
                .try_into()
                .unwrap(),
        })
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    TransparentTransactionVar<C, CVar>
{
    pub fn enforce_valid(&self, sender: &PublicKeyVar<C, CVar>) -> Result<(), SynthesisError> {
        for i in &self.inputs {
            i.pk.key
                .conditional_enforce_equal(&sender.key, &!&i.is_dummy)?;
        }
        let mut sum = FpVar::zero();
        for i in &self.inputs {
            sum += i.is_dummy.select(&FpVar::zero(), &i.amount)?;
        }
        for o in &self.outputs {
            sum -= o.is_dummy.select(&FpVar::zero(), &o.amount)?;
        }
        sum.enforce_equal(&FpVar::zero())?;
        Ok(())
    }

    pub fn get_signer(&self) -> Result<PublicKeyVar<C, CVar>, SynthesisError> {
        let mut pk = PublicKeyVar::new_constant(ConstraintSystemRef::None, PublicKey::default())?;
        // Skip dummy UTXOs and return the public key of the last non-dummy UTXO.
        for i in &self.inputs {
            pk = i.is_dummy.select(&pk, &i.pk)?;
        }
        Ok(pk)
    }
}

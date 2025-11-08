use std::{convert::TryInto, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use crate::{
    datastructures::{
        keypair::{constraints::PublicKeyVar, PublicKey},
        utxo::constraints::UTXOVar,
        TX_IO_SIZE,
    },
    primitives::{crh::constraints::TransactionVarCRH, sparsemt::constraints::SparseConfigGadget},
    TX_TREE_HEIGHT,
};

use super::{Transaction, TransactionTreeConfig};

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    TryInto<Vec<FpVar<C::BaseField>>> for &TransactionVar<C, CVar>
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
pub struct TransactionVar<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>> {
    pub inputs: [UTXOVar<C, CVar>; TX_IO_SIZE],
    pub outputs: [UTXOVar<C, CVar>; TX_IO_SIZE],
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<Transaction<C>, C::BaseField> for TransactionVar<C, CVar>
{
    fn new_variable<T: Borrow<Transaction<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let Transaction { inputs, outputs } = f.borrow();
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

#[derive(Clone, Debug)]
pub struct TransactionTreeConfigGadget<C, CVar> {
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    ConfigGadget<TransactionTreeConfig<C>, C::BaseField> for TransactionTreeConfigGadget<C, CVar>
{
    type Leaf = TransactionVar<C, CVar>;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = TransactionVarCRH<C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    SparseConfigGadget<TransactionTreeConfig<C>, C::BaseField> for TransactionTreeConfigGadget<C, CVar>
{
    const HEIGHT: u64 = TX_TREE_HEIGHT;
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    TransactionVar<C, CVar>
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

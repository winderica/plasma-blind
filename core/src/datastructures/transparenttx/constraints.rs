use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    groups::CurveVar,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};

use crate::datastructures::{
    TX_IO_SIZE,
    utxo::constraints::{UTXOInfoVar, UTXOVar},
};

use super::TransparentTransaction;

#[derive(Clone, Debug)]
pub struct TransparentTransactionVar<F: PrimeField> {
    pub inputs: [UTXOVar<F>; TX_IO_SIZE],
    pub inputs_info: [UTXOInfoVar<F>; TX_IO_SIZE],
    pub outputs: [UTXOVar<F>; TX_IO_SIZE],
}

impl<F: PrimeField> AllocVar<TransparentTransaction<F>, F> for TransparentTransactionVar<F> {
    fn new_variable<T: Borrow<TransparentTransaction<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let TransparentTransaction {
            inputs,
            inputs_info,
            outputs,
        } = f.borrow();
        Ok(Self {
            inputs: Vec::new_variable(cs.clone(), || Ok(&inputs[..]), mode)?
                .try_into()
                .unwrap(),
            inputs_info: Vec::new_variable(cs.clone(), || Ok(&inputs_info[..]), mode)?
                .try_into()
                .unwrap(),
            outputs: Vec::new_variable(cs.clone(), || Ok(&outputs[..]), mode)?
                .try_into()
                .unwrap(),
        })
    }
}

impl<F: PrimeField> TransparentTransactionVar<F> {
    pub fn enforce_valid(&self, sender: &FpVar<F>) -> Result<(), SynthesisError> {
        for i in &self.inputs {
            i.pk.conditional_enforce_equal(sender, &!&i.is_dummy)?;
        }
        let mut sum = FpVar::zero();
        for i in &self.inputs {
            sum += i.is_dummy.select(&FpVar::zero(), &i.amount.to_fp()?)?;
        }
        for o in &self.outputs {
            sum -= o.is_dummy.select(&FpVar::zero(), &o.amount.to_fp()?)?;
        }
        sum.enforce_equal(&FpVar::zero())?;
        Ok(())
    }

    pub fn get_signer(&self) -> Result<FpVar<F>, SynthesisError> {
        let mut pk = FpVar::zero();
        // Skip dummy UTXOs and return the public key of the last non-dummy UTXO.
        for i in &self.inputs {
            pk = i.is_dummy.select(&pk, &i.pk)?;
        }
        Ok(pk)
    }
}

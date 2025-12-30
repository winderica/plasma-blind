use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    uint64::UInt64,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};

use super::UTXO;
use crate::datastructures::utxo::UTXOInfo;

#[derive(Clone, Debug)]
pub struct UTXOVar<F: PrimeField> {
    pub amount: UInt64<F>,
    pub pk: FpVar<F>,
    pub salt: FpVar<F>,
    pub is_dummy: Boolean<F>,
}

#[derive(Clone, Debug)]
pub struct UTXOInfoVar<F: PrimeField> {
    pub from: FpVar<F>,
    pub utxo_index: FpVar<F>,
    pub tx_index: FpVar<F>,
    pub block_height: FpVar<F>,
}

impl<F: PrimeField> AllocVar<UTXO<F>, F> for UTXOVar<F> {
    fn new_variable<T: Borrow<UTXO<F>>>(
        cs: impl Into<Namespace<F>>,
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
            amount: UInt64::new_variable(cs.clone(), || Ok(amount), mode)?,
            pk: FpVar::new_variable(cs.clone(), || Ok(*pk), mode)?,
            salt: FpVar::new_variable(cs.clone(), || Ok(*salt), mode)?,
            is_dummy: Boolean::new_variable(cs.clone(), || Ok(is_dummy), mode)?,
        })
    }
}

impl<F: PrimeField> AllocVar<UTXOInfo<F>, F> for UTXOInfoVar<F> {
    fn new_variable<T: Borrow<UTXOInfo<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let UTXOInfo {
            from,
            utxo_index,
            tx_index,
            block_height,
        } = f.borrow();
        Ok(Self {
            from: FpVar::new_variable(cs.clone(), || Ok(from), mode)?,
            utxo_index: FpVar::new_variable(cs.clone(), || Ok(F::from(*utxo_index as u64)), mode)?,
            tx_index: FpVar::new_variable(cs.clone(), || Ok(F::from(*tx_index as u64)), mode)?,
            block_height: FpVar::new_variable(cs.clone(), || Ok(F::from(*block_height as u64)), mode)?,
        })
    }
}

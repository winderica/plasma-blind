use std::{borrow::Borrow, fmt::Debug};

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    uint64::UInt64,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use sonobe_fs::{FoldingSchemeDef, FoldingSchemeGadgetDef, GroupBasedFoldingSchemePrimaryDef};
use sonobe_primitives::{
    commitments::{VectorCommitmentDef, VectorCommitmentGadgetDef},
    transcripts::{Absorbable, AbsorbableGadget},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceState<F> {
    pub balance: u64,
    pub nonce: F,
    pub pk: F,
    pub acc: F,
    pub block_hash: F,
    pub block_number: usize,
    pub processed_tx_index: usize,
}

impl<F: Absorbable> Absorbable for BalanceState<F> {
    fn absorb_into<G: PrimeField>(&self, dest: &mut Vec<G>) {
        let Self {
            balance,
            nonce,
            pk,
            acc,
            block_hash,
            block_number,
            processed_tx_index,
        } = self;
        (*balance as usize).absorb_into(dest);
        nonce.absorb_into(dest);
        pk.absorb_into(dest);
        acc.absorb_into(dest);
        block_hash.absorb_into(dest);
        block_number.absorb_into(dest);
        processed_tx_index.absorb_into(dest);
    }
}

pub struct BalanceStateVar<F: PrimeField> {
    pub balance: FpVar<F>,
    pub nonce: FpVar<F>,
    pub pk: FpVar<F>,
    pub acc: FpVar<F>,
    pub block_hash: FpVar<F>,
    pub block_number: UInt64<F>,
    pub processed_tx_index: UInt64<F>,
}

impl<F: PrimeField> AbsorbableGadget<F> for BalanceStateVar<F> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        let Self {
            balance,
            nonce,
            pk,
            acc,
            block_hash,
            block_number,
            processed_tx_index,
        } = self;
        balance.absorb_into(dest)?;
        nonce.absorb_into(dest)?;
        pk.absorb_into(dest)?;
        acc.absorb_into(dest)?;
        block_hash.absorb_into(dest)?;
        block_number.to_fp()?.absorb_into(dest)?;
        processed_tx_index.to_fp()?.absorb_into(dest)?;

        Ok(())
    }
}

impl<F: PrimeField> AllocVar<BalanceState<F>, F> for BalanceStateVar<F> {
    fn new_variable<T: Borrow<BalanceState<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let BalanceState {
            balance,
            nonce,
            pk,
            acc,
            block_hash,
            block_number,
            processed_tx_index,
        } = v.borrow();
        Ok(Self {
            balance: AllocVar::new_variable(cs.clone(), || Ok(F::from(*balance)), mode)?,
            nonce: AllocVar::new_variable(cs.clone(), || Ok(nonce), mode)?,
            pk: AllocVar::new_variable(cs.clone(), || Ok(pk), mode)?,
            acc: AllocVar::new_variable(cs.clone(), || Ok(acc), mode)?,
            block_hash: AllocVar::new_variable(cs.clone(), || Ok(block_hash), mode)?,
            block_number: AllocVar::new_variable(cs.clone(), || Ok(*block_number as u64), mode)?,
            processed_tx_index: AllocVar::new_variable(
                cs.clone(),
                || Ok(*processed_tx_index as u64),
                mode,
            )?,
        })
    }
}

impl<F: PrimeField> GR1CSVar<F> for BalanceStateVar<F> {
    type Value = BalanceState<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.balance
            .cs()
            .or(self.nonce.cs())
            .or(self.pk.cs())
            .or(self.acc.cs())
            .or(self.block_hash.cs())
            .or(self.block_number.cs())
            .or(self.processed_tx_index.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(BalanceState {
            balance: {
                let v = self.balance
                    .value()?
                    .into_bigint().into();
                v.try_into().map_err(|_| SynthesisError::Unsatisfiable)?
            },
            nonce: self.nonce.value()?,
            pk: self.pk.value()?,
            acc: self.acc.value()?,
            block_hash: self.block_hash.value()?,
            block_number: self.block_number.value()? as usize,
            processed_tx_index: self.processed_tx_index.value()? as usize,
        })
    }
}

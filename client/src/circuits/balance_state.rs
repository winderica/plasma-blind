use std::fmt::Debug;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, GR1CSVar};
use sonobe_fs::{FoldingSchemeDef, FoldingSchemeGadgetDef, GroupBasedFoldingSchemePrimaryDef};
use sonobe_primitives::{
    commitments::{VectorCommitmentDef, VectorCommitmentGadgetDef},
    transcripts::{Absorbable, AbsorbableGadget},
};

pub struct BalanceState<FS1: FoldingSchemeDef> {
    pub balance: FS1::TranscriptField,
    pub nonce: FS1::TranscriptField,
    pub pk: FS1::TranscriptField,
    pub acc: FS1::TranscriptField,
    pub block_hash: FS1::TranscriptField,
    pub block_number: FS1::TranscriptField,
    pub processed_tx_index: FS1::TranscriptField,
}

impl<FS1: FoldingSchemeDef> Absorbable for BalanceState<FS1> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let Self {
            balance,
            nonce,
            pk,
            acc,
            block_hash,
            block_number,
            processed_tx_index,
        } = self;
        balance.absorb_into(dest);
        nonce.absorb_into(dest);
        pk.absorb_into(dest);
        acc.absorb_into(dest);
        block_hash.absorb_into(dest);
        block_number.absorb_into(dest);
        processed_tx_index.absorb_into(dest);
    }
}

impl<FS1: FoldingSchemeDef> Clone for BalanceState<FS1> {
    fn clone(&self) -> Self {
        Self {
            balance: self.balance.clone(),
            nonce: self.nonce.clone(),
            pk: self.pk.clone(),
            acc: self.acc.clone(),
            block_hash: self.block_hash.clone(),
            block_number: self.block_number.clone(),
            processed_tx_index: self.processed_tx_index.clone(),
        }
    }
}

impl<FS1: FoldingSchemeDef> Debug for BalanceState<FS1> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BalanceState")
            .field("balance", &self.balance)
            .field("nonce", &self.nonce)
            .field("pk", &self.pk)
            .field("acc", &self.acc)
            .field("block_hash", &self.block_hash)
            .field("block_number", &self.block_number)
            .field("processed_tx_index", &self.processed_tx_index)
            .finish()
    }
}

impl<FS1: FoldingSchemeDef> PartialEq for BalanceState<FS1> {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            balance,
            nonce,
            pk,
            acc,
            block_hash,
            block_number,
            processed_tx_index,
        } = self;

        balance == &other.balance
            && nonce == &other.nonce
            && pk == &other.pk
            && acc == &other.acc
            && block_hash == &other.block_hash
            && block_number == &other.block_number
            && processed_tx_index == &other.processed_tx_index
    }
}

impl<FS1: FoldingSchemeDef> Eq for BalanceState<FS1> {}

pub struct BalanceStateVar<FS1: FoldingSchemeDef<TranscriptField: Absorb>> {
    pub balance: FpVar<FS1::TranscriptField>,
    pub nonce: FpVar<FS1::TranscriptField>,
    pub pk: FpVar<FS1::TranscriptField>,
    pub acc: FpVar<FS1::TranscriptField>,
    pub block_hash: FpVar<FS1::TranscriptField>,
    pub block_number: FpVar<FS1::TranscriptField>,
    pub processed_tx_index: FpVar<FS1::TranscriptField>,
}

impl<FS1: FoldingSchemeDef<TranscriptField: Absorb>> AbsorbableGadget<FS1::TranscriptField>
    for BalanceStateVar<FS1>
{
    fn absorb_into(
        &self,
        dest: &mut Vec<ark_r1cs_std::fields::fp::FpVar<FS1::TranscriptField>>,
    ) -> Result<(), ark_relations::gr1cs::SynthesisError> {
        let Self {
            balance,
            nonce,
            pk,
            acc,
            block_hash,
            block_number,
            processed_tx_index,
        } = self;
        balance.absorb_into(dest);
        nonce.absorb_into(dest);
        pk.absorb_into(dest);
        acc.absorb_into(dest);
        block_hash.absorb_into(dest);
        block_number.absorb_into(dest);
        processed_tx_index.absorb_into(dest);

        Ok(())
    }
}

impl<FS1: FoldingSchemeDef<TranscriptField: Absorb>>
    AllocVar<BalanceState<FS1>, FS1::TranscriptField> for BalanceStateVar<FS1>
{
    fn new_variable<T: std::borrow::Borrow<BalanceState<FS1>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<FS1::TranscriptField>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
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
            balance: AllocVar::new_variable(cs.clone(), || Ok(balance), mode)?,
            nonce: AllocVar::new_variable(cs.clone(), || Ok(nonce), mode)?,
            pk: AllocVar::new_variable(cs.clone(), || Ok(pk), mode)?,
            acc: AllocVar::new_variable(cs.clone(), || Ok(acc), mode)?,
            block_hash: AllocVar::new_variable(cs.clone(), || Ok(block_hash), mode)?,
            block_number: AllocVar::new_variable(cs.clone(), || Ok(block_number), mode)?,
            processed_tx_index: AllocVar::new_variable(
                cs.clone(),
                || Ok(processed_tx_index),
                mode,
            )?,
        })
    }
}

impl<FS1: FoldingSchemeDef<TranscriptField: Absorb>> GR1CSVar<FS1::TranscriptField>
    for BalanceStateVar<FS1>
{
    type Value = BalanceState<FS1>;

    fn cs(&self) -> ark_relations::gr1cs::ConstraintSystemRef<FS1::TranscriptField> {
        self.balance
            .cs()
            .or(self.nonce.cs())
            .or(self.pk.cs())
            .or(self.acc.cs())
            .or(self.block_hash.cs())
            .or(self.block_number.cs())
            .or(self.processed_tx_index.cs())
    }

    fn value(&self) -> Result<Self::Value, ark_relations::gr1cs::SynthesisError> {
        Ok(BalanceState {
            balance: self.balance.value()?,
            nonce: self.nonce.value()?,
            pk: self.pk.value()?,
            acc: self.acc.value()?,
            block_hash: self.block_hash.value()?,
            block_number: self.block_number.value()?,
            processed_tx_index: self.processed_tx_index.value()?,
        })
    }
}

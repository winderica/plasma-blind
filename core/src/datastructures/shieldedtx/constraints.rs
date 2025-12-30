use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};

use super::{SHIELDED_TX_TREE_HEIGHT, ShieldedTransaction, ShieldedTransactionConfig};
use crate::{
    datastructures::nullifier::constraints::NullifierVar,
    primitives::{
        crh::constraints::IdentityCRHGadget,
        sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
    },
};

#[derive(Clone, Debug)]
pub struct ShieldedTransactionVar<F: PrimeField> {
    pub input_nullifiers: Vec<NullifierVar<F>>,
    pub output_utxo_commitments: Vec<FpVar<F>>,
}

impl<F: PrimeField> AllocVar<ShieldedTransaction<F>, F>
    for ShieldedTransactionVar<F>
{
    fn new_variable<T: std::borrow::Borrow<ShieldedTransaction<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let res = f()?;
        let tx: &ShieldedTransaction<F> = res.borrow();
        Ok(ShieldedTransactionVar {
            input_nullifiers: Vec::new_variable(cs.clone(), || Ok(&tx.input_nullifiers[..]), mode)?,
            output_utxo_commitments: Vec::new_variable(
                cs.clone(),
                || Ok(&tx.output_utxo_commitments[..]),
                mode,
            )?,
        })
    }
}

pub type UTXOTreeGadget<F> = MerkleSparseTreeGadget<
        ShieldedTransactionConfig<F>,
        F,
        ShieldedTransactionConfigGadget<F>,
    >;

#[derive(Clone, Debug)]
pub struct ShieldedTransactionConfigGadget<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> ConfigGadget<ShieldedTransactionConfig<F>, F>
    for ShieldedTransactionConfigGadget<F>
{
    type Leaf = FpVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = IdentityCRHGadget<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField + Absorb> SparseConfigGadget<ShieldedTransactionConfig<F>, F>
    for ShieldedTransactionConfigGadget<F>
{
    const HEIGHT: usize = SHIELDED_TX_TREE_HEIGHT;
}

use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar};

use super::{SHIELDED_TX_TREE_HEIGHT, ShieldedTransaction, ShieldedTransactionConfig};
use crate::{
    datastructures::{
        keypair::constraints::PublicKeyVar, nullifier::constraints::NullifierVar,
        utxo::constraints::UTXOVar,
    },
    primitives::{
        crh::constraints::{IdentityCRHGadget, UTXOVarCRH},
        sparsemt::constraints::SparseConfigGadget,
    },
};

#[derive(Clone, Debug)]
pub struct ShieldedTransactionVar<C: CurveGroup<BaseField: PrimeField>> {
    pub input_nullifiers: Vec<NullifierVar<C::BaseField>>,
    pub output_utxo_commitments: Vec<FpVar<C::BaseField>>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> AllocVar<ShieldedTransaction<C>, C::BaseField>
    for ShieldedTransactionVar<C>
{
    fn new_variable<T: std::borrow::Borrow<ShieldedTransaction<C>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let res = f()?;
        let tx: &ShieldedTransaction<C> = res.borrow();
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

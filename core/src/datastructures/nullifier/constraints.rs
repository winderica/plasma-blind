use std::marker::PhantomData;

use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::crh::poseidon::constraints::TwoToOneCRHGadget;
use ark_crypto_primitives::merkle_tree::IdentityDigestConverter;
use ark_crypto_primitives::merkle_tree::constraints::ConfigGadget;
use ark_crypto_primitives::{
    crh::poseidon::constraints::{CRHGadget, CRHParametersVar},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

use crate::datastructures::nullifier::NullifierTreeConfig;
use crate::primitives::crh::constraints::NullifierVarCRH;
use crate::primitives::sparsemt::constraints::SparseConfigGadget;

use super::Nullifier;

#[derive(Clone, Debug)]
pub struct NullifierVar<F: PrimeField> {
    pub value: FpVar<F>,
}

impl<F: PrimeField + Absorb> NullifierVar<F> {
    pub fn new(
        cfg: &CRHParametersVar<F>,
        sk: &FpVar<F>,
        utxo_idx: FpVar<F>,
        tx_idx: FpVar<F>,
        block_height: FpVar<F>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            value: CRHGadget::evaluate(cfg, &[sk.clone(), utxo_idx, tx_idx, block_height])?,
        })
    }
}

impl<F: PrimeField> AllocVar<Nullifier<F>, F> for NullifierVar<F> {
    fn new_variable<T: std::borrow::Borrow<Nullifier<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let res = f()?;
        let nullifier = res.borrow();
        Ok(NullifierVar {
            value: FpVar::new_variable(cs, || Ok(nullifier.value), mode)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NullifierTreeConfigGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb>
    ConfigGadget<NullifierTreeConfig<F>, F> for NullifierTreeConfigGadget<F>
{
    type Leaf = NullifierVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = NullifierVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField + Absorb>
    SparseConfigGadget<NullifierTreeConfig<F>, F> for NullifierTreeConfigGadget<F>
{
    const HEIGHT: usize = 32;
}

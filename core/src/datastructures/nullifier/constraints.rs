use sonobe_primitives::transcripts::Absorbable;
use sonobe_primitives::transcripts::griffin::constraints::crh::GriffinParamsVar;
use sonobe_primitives::transcripts::griffin::sponge::GriffinSpongeVar;
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
use ark_r1cs_std::prelude::{Boolean, ToBitsGadget};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

use super::Nullifier;
use crate::datastructures::nullifier::NullifierTreeConfig;
use crate::datastructures::utxo::constraints::UTXOInfoVar;
use crate::primitives::crh::constraints::IntervalCRHGadget;
use crate::primitives::sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget};

#[derive(Clone, Debug)]
pub struct NullifierVar<F: PrimeField> {
    pub value: FpVar<F>,
}

impl<F: PrimeField + Absorb + Absorbable> NullifierVar<F> {
    pub fn new(
        cfg: &GriffinParamsVar<F>,
        sk: &FpVar<F>,
        utxo_info: &UTXOInfoVar<F>,
    ) -> Result<Self, SynthesisError> {
        let digest = GriffinSpongeVar::evaluate(
            cfg,
            &[
                sk.clone(),
                utxo_info.utxo_index.clone(),
                utxo_info.tx_index.clone(),
                utxo_info.block_height.clone(),
            ],
        )?;

        Ok(Self {
            value: Boolean::le_bits_to_fp(&digest.to_bits_le()?[1..F::MODULUS_BIT_SIZE as usize])?,
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

pub type NullifierTreeGadgeet<F> =
    MerkleSparseTreeGadget<NullifierTreeConfig<F>, F, NullifierTreeConfigGadget<F>>;

#[derive(Clone, Debug)]
pub struct NullifierTreeConfigGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> ConfigGadget<NullifierTreeConfig<F>, F>
    for NullifierTreeConfigGadget<F>
{
    type Leaf = (FpVar<F>, FpVar<F>);
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = IntervalCRHGadget<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField + Absorb> SparseConfigGadget<NullifierTreeConfig<F>, F>
    for NullifierTreeConfigGadget<F>
{
    const HEIGHT: usize = 32;
}

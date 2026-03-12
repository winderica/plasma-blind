use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, poseidon::constraints::TwoToOneCRHGadget},
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::transcripts::{
    Absorbable,
    griffin::{constraints::crh::GriffinParamsVar, sponge::GriffinSpongeVar},
};

use super::Nullifier;
use crate::{
    datastructures::{nullifier::NullifierTreeConfig, utxo::constraints::UTXOInfoVar},
    primitives::{
        crh::{
            constraints::{IntervalCRHGadget, NTo1CRHVar},
            utils::Init,
        },
        sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
    },
};

#[derive(Clone, Debug)]
pub struct NullifierVar<F: PrimeField> {
    pub value: FpVar<F>,
}

impl<F: PrimeField + Absorb> NullifierVar<F> {
    pub fn new<Cfg: Init<F = F>>(
        cfg: &Cfg::Var,
        sk: &FpVar<F>,
        utxo_info: &UTXOInfoVar<F>,
    ) -> Result<Self, SynthesisError> {
        let digest = Cfg::HGadget::evaluate(
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

pub type NullifierTreeGadget<Cfg> = MerkleSparseTreeGadget<
    NullifierTreeConfig<Cfg>,
    <Cfg as Init>::F,
    NullifierTreeConfigGadget<Cfg>,
>;

#[derive(Clone, Debug)]
pub struct NullifierTreeConfigGadget<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init> ConfigGadget<NullifierTreeConfig<Cfg>, Cfg::F> for NullifierTreeConfigGadget<Cfg> {
    type Leaf = (FpVar<Cfg::F>, FpVar<Cfg::F>);
    type LeafDigest = FpVar<Cfg::F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<Cfg::F>>;
    type InnerDigest = FpVar<Cfg::F>;
    type LeafHash = IntervalCRHGadget<Cfg>;
    type TwoToOneHash = NTo1CRHVar<Cfg, 2>;
}

impl<Cfg: Init> SparseConfigGadget<NullifierTreeConfig<Cfg>, Cfg::F>
    for NullifierTreeConfigGadget<Cfg>
{
    const HEIGHT: usize = 32;
}

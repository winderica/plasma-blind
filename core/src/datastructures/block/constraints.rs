use ark_crypto_primitives::{
    merkle_tree::{Config, constraints::ConfigGadget},
    sponge::{Absorb, constraints::AbsorbGadget},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, uint8::UInt8};
use ark_relations::gr1cs::SynthesisError;

use super::Block;

pub type BlockHashVar<F> = FpVar<F>;

// I'm not sure we need the nullifier tree in the block?
#[derive(Clone, Debug)]
pub struct BlockVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: Config, // transaction tree config
    TCG: ConfigGadget<TC, C::BaseField>,
    SC: Config,
    SCG: ConfigGadget<SC, C::BaseField>,
> {
    pub tx_tree_root: TCG::InnerDigest,
    pub signer_tree_root: SCG::InnerDigest,
    pub height: FpVar<C::BaseField>,
}

impl<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: Config, // transaction tree config
    TCG: ConfigGadget<TC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
    SC: Config,
    SCG: ConfigGadget<SC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
> AllocVar<Block<C::BaseField>, C::BaseField> for BlockVar<C, TC, TCG, SC, SCG>
{
    fn new_variable<T: std::borrow::Borrow<Block<C::BaseField>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let res = f()?;
        let block = res.borrow();
        let tx_tree_root = <TCG as ConfigGadget<TC, C::BaseField>>::InnerDigest::new_variable(
            cs.clone(),
            || Ok(block.tx_tree_root),
            mode,
        )?;
        let signer_tree_root = <SCG as ConfigGadget<SC, C::BaseField>>::InnerDigest::new_variable(
            cs.clone(),
            || Ok(block.signer_tree_root),
            mode,
        )?;
        let height = FpVar::new_variable(
            cs.clone(),
            || Ok(C::BaseField::from(block.height as u64)),
            mode,
        )?;
        Ok(BlockVar {
            tx_tree_root,
            signer_tree_root,
            height,
        })
    }
}

impl<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: Config, // transaction tree config
    TCG: ConfigGadget<TC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
    SC: Config,
    SCG: ConfigGadget<SC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
> AbsorbGadget<C::BaseField> for BlockVar<C, TC, TCG, SC, SCG>
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<C::BaseField>>, SynthesisError> {
        Ok([
            self.tx_tree_root.to_sponge_bytes()?,
            self.signer_tree_root.to_sponge_bytes()?,
            self.height.to_sponge_bytes()?,
        ]
        .concat())
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError> {
        Ok(vec![
            self.tx_tree_root.clone(),
            self.signer_tree_root.clone(),
            self.height.clone(),
        ])
    }
}

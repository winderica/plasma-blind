use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, uint8::UInt8};
use ark_relations::gr1cs::SynthesisError;

use super::Block;

pub type BlockHashVar<F> = FpVar<F>;

// I'm not sure we need the nullifier tree in the block?
#[derive(Clone, Debug)]
pub struct BlockVar<F: PrimeField> {
    pub tx_tree_root: FpVar<F>,
    pub signer_tree_root: FpVar<F>,
    pub height: FpVar<F>,
}

impl<F: PrimeField> AllocVar<Block<F>, F> for BlockVar<F> {
    fn new_variable<T: std::borrow::Borrow<Block<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let res = f()?;
        let block = res.borrow();
        let tx_tree_root = FpVar::new_variable(cs.clone(), || Ok(block.tx_tree_root), mode)?;
        let signer_tree_root =
            FpVar::new_variable(cs.clone(), || Ok(block.signer_tree_root), mode)?;
        let height = FpVar::new_variable(cs.clone(), || Ok(F::from(block.height as u64)), mode)?;
        Ok(BlockVar {
            tx_tree_root,
            signer_tree_root,
            height,
        })
    }
}

impl<F: PrimeField> AbsorbGadget<F> for BlockVar<F> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([
            self.tx_tree_root.to_sponge_bytes()?,
            self.signer_tree_root.to_sponge_bytes()?,
            self.height.to_sponge_bytes()?,
        ]
        .concat())
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![
            self.tx_tree_root.clone(),
            self.signer_tree_root.clone(),
            self.height.clone(),
        ])
    }
}

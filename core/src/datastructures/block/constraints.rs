use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, uint64::UInt64};

use crate::datastructures::block::BlockMetadata;


// I'm not sure we need the nullifier tree in the block?
#[derive(Clone, Debug)]
pub struct BlockMetadataVar<F: PrimeField> {
    pub tx_tree_root: FpVar<F>,
    pub signer_tree_root: FpVar<F>,
    pub nullifier_tree_root: FpVar<F>,
    pub height: UInt64<F>,
}

impl<F: PrimeField> AllocVar<BlockMetadata<F>, F> for BlockMetadataVar<F> {
    fn new_variable<T: std::borrow::Borrow<BlockMetadata<F>>>(
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
        let nullifier_tree_root =
            FpVar::new_variable(cs.clone(), || Ok(block.nullifier_tree_root), mode)?;
        let height = UInt64::new_variable(cs.clone(), || Ok(block.height as u64), mode)?;
        Ok(BlockMetadataVar {
            tx_tree_root,
            signer_tree_root,
            nullifier_tree_root,
            height,
        })
    }
}

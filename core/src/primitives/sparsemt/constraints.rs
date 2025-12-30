
use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget, TwoToOneCRHSchemeGadget,
    },
    merkle_tree::{Config, constraints::ConfigGadget},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::algebra::ops::bits::ToBitsGadgetExt;

use crate::primitives::sparsemt::SparseConfig;

pub trait SparseConfigGadget<P: Config, F: PrimeField>: ConfigGadget<P, F> {
    const HEIGHT: usize;
}

pub struct MerkleSparseTreeGadget<MP: Config, F: PrimeField, P: SparseConfigGadget<MP, F>> {
    pub leaf_hash_params: <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
    pub inner_hash_params:
        <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::ParametersVar,
}

impl<
    MP: Config,
    F: PrimeField,
    P: SparseConfigGadget<
            MP,
            F,
            Leaf: Sized,
            LeafDigest = FpVar<F>,
            InnerDigest = FpVar<F>,
            TwoToOneHash: TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F, InputVar = FpVar<F>>,
        >,
> MerkleSparseTreeGadget<MP, F, P>
{
    pub fn new(
        leaf_hash_params: <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        inner_hash_params:
        <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::ParametersVar,
    ) -> Self {
        Self {
            leaf_hash_params,
            inner_hash_params,
        }
    }

    /// check a lookup proof (with index)
    pub fn check_index(
        &self,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        index: &impl ToBitsGadgetExt<F>,
        proof: &[P::InnerDigest],
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_index(root, leaf, index, proof, &Boolean::TRUE)
    }

    pub fn is_at_index(
        &self,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        index: &impl ToBitsGadgetExt<F>,
        proof: &[P::InnerDigest],
    ) -> Result<Boolean<F>, SynthesisError> {
        self.recover_root(leaf, &index.to_n_bits_le((P::HEIGHT - 1))?, proof)?
            .is_eq(root)
    }

    pub fn build_root(&self, leaves: &[P::Leaf]) -> Result<P::InnerDigest, SynthesisError> {
        assert_eq!(leaves.len(), 1 << (P::HEIGHT - 1));

        let mut hashes = leaves
            .iter()
            .map(|leaf| P::LeafHash::evaluate(&self.leaf_hash_params, leaf))
            .collect::<Result<Vec<_>, _>>()?;

        while hashes.len() > 1 {
            hashes = hashes
                .chunks(2)
                .map(|pair| P::TwoToOneHash::evaluate(&self.inner_hash_params, &pair[0], &pair[1]))
                .collect::<Result<_, _>>()?;
        }

        Ok(hashes.swap_remove(0))
    }

    pub fn recover_root(
        &self,
        leaf: &P::Leaf,
        index_bits: &[Boolean<F>],
        proof: &[P::InnerDigest],
    ) -> Result<P::InnerDigest, SynthesisError> {
        assert_eq!(proof.len(), ((P::HEIGHT - 1)));

        let mut hash = P::LeafHash::evaluate(&self.leaf_hash_params, leaf)?;
        for (neighbor, neighbor_is_left) in proof.iter().zip(index_bits) {
            let left = neighbor_is_left.select(neighbor, &hash)?;
            let right = hash + neighbor - &left;

            hash = P::TwoToOneHash::evaluate(&self.inner_hash_params, &left, &right)?;
        }

        Ok(hash)
    }

    /// conditionally check a lookup proof (with index)
    pub fn conditionally_check_index(
        &self,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        index: &impl ToBitsGadgetExt<F>,
        proof: &[P::InnerDigest],
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        self.recover_root(leaf, &index.to_n_bits_le((P::HEIGHT - 1))?, proof)?
            .conditional_enforce_equal(root, should_enforce)
    }

    /// Update root
    pub fn update_root(
        &self,
        old_leaf: &P::Leaf,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
        proof: &[P::InnerDigest],
    ) -> Result<(P::InnerDigest, P::InnerDigest), SynthesisError> {
        let index_bits = index.to_n_bits_le((P::HEIGHT - 1))?;
        Ok((
            self.recover_root(old_leaf, &index_bits, proof)?,
            self.recover_root(new_leaf, &index_bits, proof)?,
        ))
    }

    /// check a modifying proof
    pub fn check_update(
        &self,
        old_root: &P::InnerDigest,
        new_root: &P::InnerDigest,
        old_leaf: &P::Leaf,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
        proof: &[P::InnerDigest],
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_update(
            old_root,
            new_root,
            old_leaf,
            new_leaf,
            index,
            proof,
            &Boolean::TRUE,
        )
    }

    /// conditionally check a modifying proof
    pub fn conditionally_check_update(
        &self,
        old_root: &P::InnerDigest,
        new_root: &P::InnerDigest,
        old_leaf: &P::Leaf,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
        proof: &[P::InnerDigest],
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let (old_hash, new_hash) = self.update_root(old_leaf, new_leaf, index, proof)?;
        old_root.conditional_enforce_equal(&old_hash, should_enforce)?;
        new_root.conditional_enforce_equal(&new_hash, should_enforce)?;
        Ok(())
    }
}

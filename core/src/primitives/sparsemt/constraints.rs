use std::{borrow::Borrow, ops::Not};

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget, TwoToOneCRHSchemeGadget,
        poseidon::{TwoToOneCRH, constraints::TwoToOneCRHGadget},
    },
    merkle_tree::{Config, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::gr1cs::{Namespace, SynthesisError};

use super::{MerkleSparseTreePath, MerkleSparseTreeTwoPaths, SparseConfig};

pub trait SparseConfigGadget<P: Config, F: PrimeField>: ConfigGadget<P, F> {
    const HEIGHT: u64;
}

/// Gadgets for one Merkle tree path
#[derive(Debug, Clone)]
pub struct MerkleSparseTreePathVar<MP: Config, F: PrimeField, P: SparseConfigGadget<MP, F>> {
    path: Vec<(P::InnerDigest, P::InnerDigest)>,
}

/// Gadgets for two Merkle tree paths
#[derive(Debug, Clone)]
pub struct MerkleSparseTreeTwoPathsVar<MP: Config, F: PrimeField, P: SparseConfigGadget<MP, F>> {
    path: Vec<P::InnerDigest>,
}

impl<
    MP: Config<TwoToOneHash = TwoToOneCRH<F>>,
    F: PrimeField + Absorb,
    P: SparseConfigGadget<
            MP,
            F,
            LeafDigest = FpVar<F>,
            InnerDigest = FpVar<F>,
            TwoToOneHash = TwoToOneCRHGadget<F>,
        >,
> MerkleSparseTreePathVar<MP, F, P>
{
    /// check a lookup proof (does not enforce index consistency)
    pub fn check_membership(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership(
            leaf_hash_params,
            two_to_one_hash_params,
            root,
            leaf,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a lookup proof (does not enforce index consistency)
    pub fn conditionally_check_membership(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        // let leaf_bits = leaf.to_bytes()?;
        let leaf_hash =
            <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::evaluate(leaf_hash_params, leaf)?;
        // let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;

        // Check if leaf is one of the bottom-most siblings.
        let leaf_is_left = Ok(Boolean::new_witness(
            ark_relations::ns!(leaf_hash.cs().or(self.path[0].0.cs()), "leaf_is_left"),
            || Ok(leaf_hash.value()? == self.path[0].0.value()?),
        )?)?;

        leaf_hash.conditional_enforce_equal(
            &leaf_is_left.select(&self.path[0].0, &self.path[0].1)?,
            should_enforce,
        )?;

        // Check levels between leaf level and root.
        let mut previous_hash = leaf_hash;
        for (left_hash, right_hash) in self.path.iter() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = Boolean::new_witness(
                ark_relations::ns!(previous_hash.cs().or(left_hash.cs()), "previous_is_left"),
                || Ok(previous_hash.value()? == left_hash.value()?),
            )?;

            previous_hash.conditional_enforce_equal(
                &previous_is_left.select(left_hash, right_hash)?,
                should_enforce,
            )?;

            previous_hash =
                <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                    two_to_one_hash_params,
                    left_hash,
                    right_hash,
                )?;
            //previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
            //    parameters, left_hash, right_hash,
            //)?;
        }

        root.conditional_enforce_equal(&previous_hash, should_enforce)
    }

    /// check a lookup proof (with index)
    pub fn check_membership_with_index<Idx: ToBitsGadget<F>>(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        index: &Idx,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership_with_index(
            leaf_hash_params,
            two_to_one_hash_params,
            root,
            leaf,
            index,
            &Boolean::TRUE,
        )
    }

    /// conditionally check a lookup proof (with index)
    pub fn conditionally_check_membership_with_index<Idx: ToBitsGadget<F>>(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        index: &Idx,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        //let leaf_bits = leaf.to_bytes()?;
        //let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;

        // Check levels between leaf level and root.
        let mut previous_hash =
            <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::evaluate(leaf_hash_params, leaf)?;
        let index_bits = index.to_bits_le()?;

        for (i, (left_hash, right_hash)) in self.path.iter().enumerate() {
            // Check if the previous_hash matches the correct current hash.
            previous_hash.conditional_enforce_equal(
                &index_bits[i].select(right_hash, left_hash)?,
                should_enforce,
            )?;

            previous_hash =
                <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                    two_to_one_hash_params,
                    left_hash,
                    right_hash,
                )?;
        }

        root.conditional_enforce_equal(&previous_hash, should_enforce)
    }
}

//pub(crate) fn hash_inner_node_gadget<H, HG, ConstraintF>(
//    parameters: &H::Parameters,
//    left_child: &HG::OutputVar,
//    right_child: &HG::OutputVar,
//) -> Result<HG::OutputVar, SynthesisError>
//where
//    ConstraintF: PrimeField,
//    H: CRHforMerkleTree,
//    HG: CRHforMerkleTreeGadget<H, ConstraintF>,
//{
//    HG::two_to_one_compress(parameters, left_child, right_child)
//}
//

impl<
    MP: Config<TwoToOneHash = TwoToOneCRH<F>>,
    F: PrimeField + Absorb,
    P: SparseConfigGadget<
            MP,
            F,
            LeafDigest = FpVar<F>,
            InnerDigest = FpVar<F>,
            TwoToOneHash = TwoToOneCRHGadget<F>,
        >,
> MerkleSparseTreeTwoPathsVar<MP, F, P>
{
    /// Update root
    pub fn update_root(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        old_leaf: &P::Leaf,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
    ) -> Result<(P::InnerDigest, P::InnerDigest), SynthesisError> {
        assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        //let new_leaf_bits = new_leaf.to_bytes()?;
        //let new_leaf_hash = CRHVar::hash_bytes(parameters, &new_leaf_bits)?;

        let old_heaf_hash = <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::evaluate(
            leaf_hash_params,
            old_leaf,
        )?;
        let new_leaf_hash = <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::evaluate(
            leaf_hash_params,
            new_leaf,
        )?;

        // Check levels between leaf level and root of the new tree.
        let mut old_hash = old_heaf_hash;
        let mut new_hash = new_leaf_hash;
        let index_bits = index.to_bits_le()?;
        for (neighbor, neighbor_is_left) in self.path.iter().zip(&index_bits) {
            let old_left = neighbor_is_left.select(neighbor, &old_hash)?;
            let old_right = old_hash + neighbor - &old_left;
            let new_left = neighbor_is_left.select(neighbor, &new_hash)?;
            let new_right = new_hash + neighbor - &new_left;

            old_hash = <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                two_to_one_hash_params,
                &old_left,
                &old_right,
            )?;
            new_hash = <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                two_to_one_hash_params,
                &new_left,
                &new_right,
            )?;
        }
        Ok((old_hash, new_hash))
    }

    /// check a modifying proof
    pub fn check_update(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        old_root: &P::InnerDigest,
        new_root: &P::InnerDigest,
        old_leaf: &P::Leaf,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_update(
            leaf_hash_params,
            two_to_one_hash_params,
            old_root,
            new_root,
            old_leaf,
            new_leaf,
            index,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a modifying proof
    pub fn conditionally_check_update(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        old_root: &P::InnerDigest,
        new_root: &P::InnerDigest,
        old_leaf: &P::Leaf,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let (old_hash, new_hash) = self.update_root(
            leaf_hash_params,
            two_to_one_hash_params,
            old_leaf,
            new_leaf,
            index,
        )?;
        old_root.conditional_enforce_equal(&old_hash, should_enforce)?;
        new_root.conditional_enforce_equal(&new_hash, should_enforce)?;
        Ok(())
    }
}

impl<MP: SparseConfig, F: PrimeField, P: SparseConfigGadget<MP, F>>
    AllocVar<MerkleSparseTreePath<MP>, F> for MerkleSparseTreePathVar<MP, F, P>
{
    fn new_variable<T: Borrow<MerkleSparseTreePath<MP>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut path = Vec::new();
        for (l, r) in f()?.borrow().path.iter() {
            let l_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "l_child"),
                || Ok(l.clone()),
                mode,
            )?;
            let r_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "r_child"),
                || Ok(r.clone()),
                mode,
            )?;
            path.push((l_hash, r_hash));
        }
        Ok(MerkleSparseTreePathVar { path })
    }
}

impl<MP: SparseConfig, F: PrimeField, P: SparseConfigGadget<MP, F>>
    AllocVar<MerkleSparseTreeTwoPaths<MP>, F> for MerkleSparseTreeTwoPathsVar<MP, F, P>
{
    fn new_variable<T: Borrow<MerkleSparseTreeTwoPaths<MP>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let MerkleSparseTreeTwoPaths { path } = t.borrow();
        Ok(MerkleSparseTreeTwoPathsVar {
            path: Vec::new_variable(cs, || Ok(&path[..]), mode)?,
        })
    }
}

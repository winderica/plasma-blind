use ark_crypto_primitives::{
    crh::poseidon::constraints::{CRHGadget, TwoToOneCRHGadget},
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use nmerkle_trees::sparse::traits::NArySparseConfigGadget;
use sonobe_primitives::transcripts::{Absorbable, griffin::sponge::GriffinSpongeVar};
use std::marker::PhantomData;

use crate::primitives::{
    crh::constraints::IdentityCRHGadget,
    sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
};

use super::{
    NARY_SIGNER_TREE_HEIGHT, SIGNER_TREE_ARITY, SignerTreeConfig, SparseNArySignerTreeConfig,
};

pub type SignerTreeGadget<F> =
    MerkleSparseTreeGadget<SignerTreeConfig<F>, F, SignerTreeConfigGadget<F>>;

pub struct SparseNArySignerTreeConfigGadget<F: Absorb + PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb + Absorbable>
    NArySparseConfigGadget<
        SIGNER_TREE_ARITY,
        SignerTreeConfig<F>,
        SignerTreeConfigGadget<F>,
        F,
        SparseNArySignerTreeConfig<F>,
    > for SparseNArySignerTreeConfigGadget<F>
{
    const HEIGHT: u64 = NARY_SIGNER_TREE_HEIGHT;
    type NToOneHash = GriffinSpongeVar<F>;
}

#[derive(Clone, Debug)]
pub struct SignerTreeConfigGadget<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> ConfigGadget<SignerTreeConfig<F>, F> for SignerTreeConfigGadget<F> {
    type Leaf = FpVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = IdentityCRHGadget<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

//impl<F: PrimeField + Absorb> SparseConfigGadget<SignerTreeConfig<F>, F>
//    for SignerTreeConfigGadget<F>
//{
//    const HEIGHT: usize = SIGNER_TREE_HEIGHT;
//}

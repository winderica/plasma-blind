use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};
use std::marker::PhantomData;

use crate::{
    SIGNER_TREE_HEIGHT,
    datastructures::keypair::constraints::PublicKeyVar,
    primitives::{
        crh::{IdentityCRH, constraints::{IdentityCRHGadget, PublicKeyVarCRH}},
        sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
    },
};

use super::SignerTreeConfig;

pub type SignerTreeGadget<F> =
    MerkleSparseTreeGadget<SignerTreeConfig<F>, F, SignerTreeConfigGadget<F>>;

#[derive(Clone, Debug)]
pub struct SignerTreeConfigGadget<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb>
    ConfigGadget<SignerTreeConfig<F>, F> for SignerTreeConfigGadget<F>
{
    type Leaf = FpVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = IdentityCRHGadget<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField + Absorb>
    SparseConfigGadget<SignerTreeConfig<F>, F> for SignerTreeConfigGadget<F>
{
    const HEIGHT: usize = SIGNER_TREE_HEIGHT;
}

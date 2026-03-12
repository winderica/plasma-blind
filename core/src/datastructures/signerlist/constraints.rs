use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use nmerkle_trees::sparse::traits::NArySparseConfigGadget;
use sonobe_primitives::transcripts::{Absorbable, griffin::sponge::GriffinSpongeVar};
use std::marker::PhantomData;

use crate::primitives::{
    crh::{constraints::{IdentityCRHGadget, NTo1CRHVar}, utils::Init},
    sparsemt::constraints::MerkleSparseTreeGadget,
};

use super::{
    NARY_SIGNER_TREE_HEIGHT, SIGNER_TREE_ARITY, SignerTreeConfig, SparseNArySignerTreeConfig,
};

pub type SignerTreeGadget<Cfg> =
    MerkleSparseTreeGadget<SignerTreeConfig<Cfg>, <Cfg as Init>::F, SignerTreeConfigGadget<Cfg>>;

pub struct SparseNArySignerTreeConfigGadget<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init>
    NArySparseConfigGadget<
        SignerTreeConfig<Cfg>,
        SignerTreeConfigGadget<Cfg>,
        <Cfg as Init>::F,
        SparseNArySignerTreeConfig<Cfg>,
    > for SparseNArySignerTreeConfigGadget<Cfg>
{
    const HEIGHT: u64 = NARY_SIGNER_TREE_HEIGHT;
    type NToOneHash = Cfg::HGadget;
}

#[derive(Clone, Debug)]
pub struct SignerTreeConfigGadget<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init> ConfigGadget<SignerTreeConfig<Cfg>, <Cfg as Init>::F> for SignerTreeConfigGadget<Cfg> {
    type Leaf = FpVar<Cfg::F>;
    type LeafDigest = FpVar<Cfg::F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<Cfg::F>>;
    type InnerDigest = FpVar<Cfg::F>;
    type LeafHash = IdentityCRHGadget<Cfg::F>;
    type TwoToOneHash = NTo1CRHVar<Cfg, 2>;
}

//impl<F: PrimeField + Absorb> SparseConfigGadget<SignerTreeConfig<F>, F>
//    for SignerTreeConfigGadget<F>
//{
//    const HEIGHT: usize = SIGNER_TREE_HEIGHT;
//}

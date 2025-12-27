use std::marker::PhantomData;

use crate::{
    SIGNER_TREE_HEIGHT,
    primitives::{
        crh::{IdentityCRH, PublicKeyCRH},
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::keypair::PublicKey;

pub mod constraints;

pub type SignerList = Vec<u32>;
pub type SignerTree<F> = MerkleSparseTree<SignerTreeConfig<F>>;

#[derive(Clone, Debug, Default)]
pub struct SignerTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for SignerTreeConfig<F> {
    type Leaf = F;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = IdentityCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for SignerTreeConfig<F> {
    const HEIGHT: usize = SIGNER_TREE_HEIGHT;
}

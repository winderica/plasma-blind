use std::marker::PhantomData;

use crate::{
    SIGNER_TREE_HEIGHT,
    primitives::{
        crh::IdentityCRH,
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
};
use ark_crypto_primitives::{
    crh::poseidon::{CRH, TwoToOneCRH},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use nmerkle_trees::sparse::{NAryMerkleSparseTree, traits::NArySparseConfig};

pub mod constraints;

pub type SignerList = Vec<u32>;
pub type SignerTree<F> = MerkleSparseTree<SignerTreeConfig<F>>;

pub type SparseNArySignerTree<F> =
    NAryMerkleSparseTree<SIGNER_TREE_ARITY, SignerTreeConfig<F>, SparseNArySignerTreeConfig<F>>;

pub const SIGNER_TREE_ARITY: usize = 3;
pub const NARY_SIGNER_TREE_HEIGHT: u64 = 6;

#[derive(Clone, Debug, Default)]
pub struct SignerTreeConfig<F> {
    _f: PhantomData<F>,
}

#[derive(Default, Clone, Debug)]
pub struct SparseNArySignerTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: Absorb + PrimeField> NArySparseConfig<SIGNER_TREE_ARITY, SignerTreeConfig<F>>
    for SparseNArySignerTreeConfig<F>
{
    type NToOneHashParams = PoseidonConfig<F>;
    type NToOneHash = CRH<F>;
    const HEIGHT: u64 = NARY_SIGNER_TREE_HEIGHT;
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

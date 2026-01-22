use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::{CRHGadget, TwoToOneCRHGadget},
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use nmerkle_trees::sparse::traits::NArySparseConfigGadget;
use sonobe_primitives::transcripts::Absorbable;

use crate::primitives::{
    crh::constraints::IdentityCRHGadget, sparsemt::constraints::MerkleSparseTreeGadget,
};

use super::TransactionTreeConfig;
use super::{NARY_TRANSACTION_TREE_HEIGHT, SparseNAryTransactionTreeConfig};

pub type TransactionTreeGadget<F> =
    MerkleSparseTreeGadget<TransactionTreeConfig<F>, F, TransactionTreeConfigGadget<F>>;

pub struct SparseNAryTransactionTreeConfigGadget<F: Absorb + PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb + Absorbable>
    NArySparseConfigGadget<
        TransactionTreeConfig<F>,
        TransactionTreeConfigGadget<F>,
        F,
        SparseNAryTransactionTreeConfig<F>,
    > for SparseNAryTransactionTreeConfigGadget<F>
{
    const HEIGHT: u64 = NARY_TRANSACTION_TREE_HEIGHT;
    type NToOneHash = CRHGadget<F>;
}

#[derive(Clone, Debug)]
pub struct TransactionTreeConfigGadget<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> ConfigGadget<TransactionTreeConfig<F>, F>
    for TransactionTreeConfigGadget<F>
{
    // leaves are shielded transactions (i.e. roots of a mt)
    type Leaf = FpVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    // the leaf hash is identity, since leaves are roots of mt
    type LeafHash = IdentityCRHGadget<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

//impl<F: PrimeField + Absorb> SparseConfigGadget<TransactionTreeConfig<F>, F>
//    for TransactionTreeConfigGadget<F>
//{
//    const HEIGHT: usize = TX_TREE_HEIGHT;
//}

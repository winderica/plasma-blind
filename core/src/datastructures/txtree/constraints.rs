use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use nmerkle_trees::sparse::traits::NArySparseConfigGadget;
use sonobe_primitives::transcripts::{Absorbable, griffin::sponge::GriffinSpongeVar};

use super::{
    NARY_TRANSACTION_TREE_HEIGHT, SparseNAryTransactionTreeConfig, TRANSACTION_TREE_ARITY,
    TransactionTreeConfig,
};
use crate::primitives::{
    crh::{constraints::{IdentityCRHGadget, NTo1CRHVar}, utils::Init},
    sparsemt::constraints::MerkleSparseTreeGadget,
};

pub type TransactionTreeGadget<Cfg> = MerkleSparseTreeGadget<
    TransactionTreeConfig<Cfg>,
    <Cfg as Init>::F,
    TransactionTreeConfigGadget<Cfg>,
>;

pub struct SparseNAryTransactionTreeConfigGadget<Cfg: Init> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init>
    NArySparseConfigGadget<
        TransactionTreeConfig<Cfg>,
        TransactionTreeConfigGadget<Cfg>,
        <Cfg as Init>::F,
        SparseNAryTransactionTreeConfig<Cfg>,
    > for SparseNAryTransactionTreeConfigGadget<Cfg>
{
    const HEIGHT: u64 = NARY_TRANSACTION_TREE_HEIGHT;
    type NToOneHash = Cfg::HGadget;
}

#[derive(Clone, Debug)]
pub struct TransactionTreeConfigGadget<Cfg: Init> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init> ConfigGadget<TransactionTreeConfig<Cfg>, <Cfg as Init>::F>
    for TransactionTreeConfigGadget<Cfg>
{
    // leaves are shielded transactions (i.e. roots of a mt)
    type Leaf = FpVar<<Cfg as Init>::F>;
    type LeafDigest = FpVar<<Cfg as Init>::F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<<Cfg as Init>::F>>;
    type InnerDigest = FpVar<<Cfg as Init>::F>;
    // the leaf hash is identity, since leaves are roots of mt
    type LeafHash = IdentityCRHGadget<Cfg::F>;
    type TwoToOneHash = NTo1CRHVar<Cfg, 2>;
}

//impl<F: PrimeField + Absorb> SparseConfigGadget<TransactionTreeConfig<F>, F>
//    for TransactionTreeConfigGadget<F>
//{
//    const HEIGHT: usize = TX_TREE_HEIGHT;
//}

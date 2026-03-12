use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{IdentityDigestConverter, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};

use super::{SHIELDED_TX_TREE_HEIGHT, ShieldedTransaction, ShieldedTransactionConfig};
use crate::{
    datastructures::nullifier::constraints::NullifierVar,
    primitives::{
        crh::{
            constraints::{IdentityCRHGadget, NTo1CRHVar},
            utils::Init,
        },
        sparsemt::constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
    },
};

#[derive(Clone, Debug)]
pub struct ShieldedTransactionVar<F: PrimeField> {
    pub input_nullifiers: Vec<NullifierVar<F>>,
    pub output_utxo_commitments: Vec<FpVar<F>>,
}

impl<F: PrimeField> AllocVar<ShieldedTransaction<F>, F> for ShieldedTransactionVar<F> {
    fn new_variable<T: std::borrow::Borrow<ShieldedTransaction<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let res = f()?;
        let tx: &ShieldedTransaction<F> = res.borrow();
        Ok(ShieldedTransactionVar {
            input_nullifiers: Vec::new_variable(cs.clone(), || Ok(&tx.input_nullifiers[..]), mode)?,
            output_utxo_commitments: Vec::new_variable(
                cs.clone(),
                || Ok(&tx.output_utxo_commitments[..]),
                mode,
            )?,
        })
    }
}

pub type UTXOTreeGadget<Cfg> = MerkleSparseTreeGadget<
    ShieldedTransactionConfig<Cfg>,
    <Cfg as Init>::F,
    ShieldedTransactionConfigGadget<Cfg>,
>;

#[derive(Clone, Debug)]
pub struct ShieldedTransactionConfigGadget<Cfg> {
    _cfg: PhantomData<Cfg>,
}

impl<Cfg: Init> ConfigGadget<ShieldedTransactionConfig<Cfg>, Cfg::F>
    for ShieldedTransactionConfigGadget<Cfg>
{
    type Leaf = FpVar<Cfg::F>;
    type LeafDigest = FpVar<Cfg::F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<Cfg::F>>;
    type InnerDigest = FpVar<Cfg::F>;
    type LeafHash = IdentityCRHGadget<Cfg::F>;
    type TwoToOneHash = NTo1CRHVar<Cfg, 2>;
}

impl<Cfg: Init> SparseConfigGadget<ShieldedTransactionConfig<Cfg>, Cfg::F>
    for ShieldedTransactionConfigGadget<Cfg>
{
    const HEIGHT: usize = SHIELDED_TX_TREE_HEIGHT;
}

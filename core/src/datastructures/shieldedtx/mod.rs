use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::primitives::{crh::UTXOCRH, sparsemt::SparseConfig};

pub mod constraints;

use super::{keypair::PublicKey, utxo::UTXO};

pub const SHIELDED_TX_TREE_HEIGHT: u64 = 3; // 4 inputs (resolving to 4 nullifiers) + 4 outputs

// what's sent to the aggregator
#[derive(Default, Clone, Debug)]
pub struct ShieldedTransaction<C: CurveGroup<BaseField: Absorb + PrimeField>> {
    pub from: PublicKey<C>, // sender
    pub shielded_tx: <ShieldedTransactionConfig<C> as Config>::InnerDigest, // root of mt
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> AsRef<ShieldedTransaction<C>>
    for ShieldedTransaction<C>
{
    fn as_ref(&self) -> &ShieldedTransaction<C> {
        self
    }
}

#[derive(Clone, Debug)]
pub struct ShieldedTransactionConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup> AsRef<UTXO<C>> for UTXO<C> {
    fn as_ref(&self) -> &UTXO<C> {
        self
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for ShieldedTransactionConfig<C> {
    type Leaf = UTXO<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = UTXOCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>> SparseConfig for ShieldedTransactionConfig<C> {
    const HEIGHT: u64 = SHIELDED_TX_TREE_HEIGHT;
}

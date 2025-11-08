use std::{
    fmt::Debug,
    marker::PhantomData,
};

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;

use crate::primitives::{
    crh::{CommittedUTXOCRH, UTXOCRH},
    sparsemt::{MerkleSparseTree, SparseConfig},
};

use super::keypair::PublicKey;

pub mod constraints;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct UTXO<C: CurveGroup> {
    pub amount: u64,
    pub pk: PublicKey<C>,
    pub is_dummy: bool,
}

impl<C: CurveGroup> Debug for UTXO<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_dummy {
            write!(f, "UTXO(dummy)")
        } else {
            write!(f, "UTXO({:?}, {})", self.pk, self.amount)
        }
    }
}

impl<C: CurveGroup> UTXO<C> {
    pub fn new(pk: PublicKey<C>, amount: u64) -> Self {
        UTXO {
            amount,
            pk,
            is_dummy: false,
        }
    }

    pub fn dummy() -> Self {
        UTXO {
            amount: 0,
            pk: PublicKey::default(),
            is_dummy: true,
        }
    }
}

impl<C: CurveGroup> Default for UTXO<C> {
    fn default() -> Self {
        UTXO::dummy()
    }
}

#[derive(Clone, Debug)]
pub struct UTXOTreeConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> Config for UTXOTreeConfig<C> {
    type Leaf = UTXO<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = UTXOCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> SparseConfig for UTXOTreeConfig<C> {
    const HEIGHT: u64 = 32;
}

#[derive(Clone, Debug)]
pub struct CommittedUTXOTreeConfig<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for CommittedUTXOTreeConfig<F> {
    type Leaf = (F, usize);
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = CommittedUTXOCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for CommittedUTXOTreeConfig<F> {
    const HEIGHT: u64 = 32;
}

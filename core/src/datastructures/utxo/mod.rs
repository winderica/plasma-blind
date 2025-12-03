use std::{fmt::Debug, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::primitives::{crh::UTXOCRH, sparsemt::SparseConfig};

use super::keypair::PublicKey;

pub mod constraints;
pub mod proof;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct UTXO<C: CurveGroup> {
    pub amount: u64,
    pub pk: PublicKey<C>,
    pub salt: u128,
    pub index: u8,
    pub is_dummy: bool,
    pub tx_index: Option<u64>, // indicates the index of the transaction in the
    // transaction tree at the time this
    // utxo has been created
    pub block_height: Option<u64>, // indicates the block at which this utxo was created
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
    pub fn new(
        pk: PublicKey<C>,
        amount: u64,
        salt: u128,
        index: u8,
        tx_index: Option<u64>,
        block_height: Option<u64>,
    ) -> Self {
        UTXO {
            amount,
            pk,
            salt,
            index,
            is_dummy: false,
            tx_index,
            block_height,
        }
    }

    pub fn dummy() -> Self {
        UTXO {
            amount: 0,
            pk: PublicKey::default(),
            salt: 0,
            index: 0,
            is_dummy: true,
            tx_index: None,
            block_height: None,
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

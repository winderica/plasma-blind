use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::primitives::crh::TransactionCRH;

use super::transaction::Transaction;

pub type WithdrawTree<P> = MerkleTree<P>;

pub struct WithdrawTreeConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for WithdrawTreeConfig<C> {
    type Leaf = Transaction<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = TransactionCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

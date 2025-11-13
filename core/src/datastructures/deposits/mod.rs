use std::marker::PhantomData;

use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_ec::CurveGroup;

pub type DepositTree<P> = MerkleTree<P>;

pub struct DepositTreeConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

// TODO
//impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for DepositTreeConfig<C> {
//    type Leaf = Transaction<C>;
//    type LeafDigest = C::BaseField;
//    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
//    type InnerDigest = C::BaseField;
//    type LeafHash = TransactionCRH<C>;
//    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
//}

use std::{iter::Map, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::{keypair::PublicKey, user::UserId};
use crate::primitives::crh::PublicKeyCRH;

pub mod constraints;

pub type PublicKeyMap<C> = Map<UserId, PublicKey<C>>;
pub type PublicKeyTree<P> = MerkleTree<P>;

pub struct PublicKeyTreeConfig<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for PublicKeyTreeConfig<C> {
    type Leaf = PublicKey<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = PublicKeyCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::merkle_tree::constraints::PathVar;
    use ark_ff::UniformRand;
    use ark_grumpkin::{Projective, constraints::GVar};
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::rand::{Rng, thread_rng};

    use crate::{
        datastructures::{
            keypair::PublicKey,
            publickeymap::{
                PublicKeyTree, PublicKeyTreeConfig, constraints::PublicKeyTreeConfigGadget,
            },
        },
        primitives::crh::poseidon_canonical_config,
    };

    #[test]
    pub fn test_public_key_tree_circuit() {
        let n_users = 2_usize.pow(10);
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let public_keys = (0..n_users)
            .map(|_| {
                let key = Projective::rand(&mut rng);
                PublicKey { key }
            })
            .collect::<Vec<PublicKey<Projective>>>();
        let public_key_tree =
            PublicKeyTree::<PublicKeyTreeConfig<Projective>>::new(&pp, &pp, &public_keys).unwrap();

        for _ in 0..100 {
            let expected_random_user_id = rng.gen_range(0..n_users);
            let user_public_key_proof = public_key_tree
                .generate_proof(expected_random_user_id)
                .unwrap();
            let expected_random_user_id_var =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(expected_random_user_id as u32)))
                    .unwrap();
            let public_key_proof_var =
                PathVar::<
                    PublicKeyTreeConfig<Projective>,
                    Fr,
                    PublicKeyTreeConfigGadget<Projective, GVar, PublicKeyTreeConfig<Projective>>,
                >::new_witness(cs.clone(), || Ok(user_public_key_proof))
                .unwrap();

            let computed_id =
                Boolean::le_bits_to_fp(&public_key_proof_var.get_leaf_position()).unwrap();
            computed_id
                .enforce_equal(&expected_random_user_id_var)
                .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
    }
}

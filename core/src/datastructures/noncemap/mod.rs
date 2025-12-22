use std::{iter::Map, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;

use super::user::UserId;
use crate::primitives::{
    crh::NonceCRH,
    sparsemt::{MerkleSparseTree, SparseConfig},
};

pub mod constraints;

pub type NonceMap = Map<UserId, Nonce>;
pub type NonceTree<P> = MerkleSparseTree<P>;

pub struct NonceTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Nonce(pub u64);

impl<F: PrimeField + Absorb> Config for NonceTreeConfig<F> {
    type Leaf = Nonce;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = NonceCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for NonceTreeConfig<F> {
    const HEIGHT: usize = 32;
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeMap;

    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, uint64::UInt64};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::rand::{Rng, thread_rng};

    use super::constraints::NonceTreeConfigGadget;
    use crate::{
        datastructures::noncemap::{Nonce, NonceTree, NonceTreeConfig},
        primitives::{
            crh::poseidon_canonical_config, sparsemt::constraints::MerkleSparseTreeGadget,
        },
    };

    #[test]
    pub fn test_nonce_map_circuit() {
        let tree_height = 5;
        let n_users = 1 << (tree_height - 1);
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let nonces = (0..n_users)
            .map(|_| Nonce(rng.gen_range(0..(u64::MAX))))
            .collect::<Vec<Nonce>>();
        let nonce_tree = NonceTree::<NonceTreeConfig<Fr>>::new(
            &pp,
            &pp,
            &BTreeMap::from_iter(nonces.clone().into_iter().enumerate()),
        )
        .unwrap();

        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();
        let mt = MerkleSparseTreeGadget::<NonceTreeConfig<Fr>, Fr, NonceTreeConfigGadget<Fr>>::new(
            pp_var.clone(),
            pp_var,
        );
        let root_var = FpVar::new_constant(cs.clone(), nonce_tree.root()).unwrap();

        for _ in 0..100 {
            let expected_random_user_id = rng.gen_range(0..n_users);
            let user_nonce_proof = nonce_tree
                .generate_proof(
                    expected_random_user_id,
                    &nonces[expected_random_user_id as usize],
                )
                .unwrap();
            let expected_user_nonce_var =
                UInt64::new_witness(
                    cs.clone(),
                    || Ok(nonces[expected_random_user_id as usize].0),
                )
                .unwrap();
            let index =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(expected_random_user_id as u64))).unwrap();
            let user_nonce_proof_var =
                Vec::new_witness(cs.clone(), || Ok(user_nonce_proof)).unwrap();

            mt.check_index(
                &root_var,
                &expected_user_nonce_var,
                &index,
                &user_nonce_proof_var,
            )
            .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
    }
}

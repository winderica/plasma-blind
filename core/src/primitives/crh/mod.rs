// Define the various CRH used in PlasmaFold
use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    Error,
    crh::{CRHScheme, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget, poseidon::CRH},
    sponge::{
        Absorb,
        constraints::CryptographicSpongeVar,
        poseidon::{PoseidonConfig, find_poseidon_ark_and_mds},
    },
};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{Field, FpConfig, PrimeField, Zero};
use ark_r1cs_std::{GR1CSVar, groups::CurveVar};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use sonobe_primitives::transcripts::{
    Absorbable,
    griffin::{GriffinParams, sponge::GriffinSponge},
};

use crate::{
    datastructures::{
        block::BlockMetadata, keypair::PublicKey, noncemap::Nonce, nullifier::Nullifier, utxo::UTXO,
    },
    primitives::crh::utils::Init,
};

pub mod constraints;
pub mod utils;

pub fn poseidon_custom_config<F: PrimeField>(
    full_rounds: usize,
    partial_rounds: usize,
    alpha: u64,
    rate: usize,
    capacity: usize,
) -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

pub fn poseidon_canonical_config<F: PrimeField>() -> PoseidonConfig<F> {
    // 120 bit security target as in
    // https://eprint.iacr.org/2019/458.pdf
    // t = rate + 1

    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;

    poseidon_custom_config(full_rounds, partial_rounds, alpha, rate, 1)
}

pub struct IdentityCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> CRHScheme for IdentityCRH<F> {
    type Input = F;
    type Output = F;
    type Parameters = ();

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        Ok(*input.borrow())
    }
}

pub struct IntervalCRH<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize> CRHScheme for IntervalCRH<Cfg> {
    type Input = (Cfg::F, Cfg::F);
    type Output = Cfg::F;
    type Parameters = Cfg;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(Cfg::init::<2>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let (l, r) = input.borrow();
        Cfg::H::evaluate(parameters, [*l, *r])
    }
}

pub struct PublicKeyCRH<Cfg, C: CurveGroup> {
    _c: PhantomData<(C, Cfg)>,
}

impl<
    Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize,
    C: CurveGroup<BaseField = Cfg::F>,
> CRHScheme for PublicKeyCRH<Cfg, C>
{
    type Input = PublicKey<C>;
    type Output = C::BaseField;
    type Parameters = Cfg;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(Cfg::init::<3>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input: &PublicKey<C> = input.borrow();
        let point = input.key.into_affine();
        if point.is_zero() {
            Ok(Cfg::H::evaluate(
                parameters,
                // flag for point is zero is true
                [C::BaseField::ZERO, C::BaseField::ZERO, C::BaseField::ONE],
            )?)
        } else {
            let (x, y) = point.xy().unwrap();
            // flag for point is zero is false
            Ok(Cfg::H::evaluate(parameters, [x, y, C::BaseField::ZERO])?)
        }
    }
}

pub struct NullifierCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> CRHScheme for NullifierCRH<F> {
    type Input = Nullifier<F>;
    type Output = F;
    type Parameters = ();

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let nullifier = input.borrow();
        Ok(nullifier.value)
    }
}
pub struct UTXOCRH<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize> CRHScheme for UTXOCRH<Cfg> {
    type Input = UTXO<Cfg::F>;
    type Output = Cfg::F;
    type Parameters = Cfg;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // WARNING: this config should be checked and not used in production as is
        Ok(Cfg::init::<4>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let utxo: &UTXO<_> = input.borrow();
        let input = [
            Cfg::F::from(utxo.amount),
            Cfg::F::from(utxo.is_dummy),
            utxo.salt,
            utxo.pk,
        ];
        Cfg::H::evaluate(parameters, input)
    }
}

pub struct BlockTreeCRH<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize> CRHScheme
    for BlockTreeCRH<Cfg>
{
    type Input = BlockMetadata<Cfg::F>;
    type Output = Cfg::F;
    type Parameters = Cfg;

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        // WARNING: this config should be checked and not used in production as is
        Ok(Cfg::init::<4>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let block = input.borrow();
        let input = [
            block.tx_tree_root,
            block.signer_tree_root,
            block.nullifier_tree_root,
            Cfg::F::from(block.height as u64),
        ];
        Cfg::H::evaluate(parameters, input)
    }
}

pub struct NTo1CRH<Cfg, const N: usize> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init, const N: usize> CRHScheme for NTo1CRH<Cfg, N> {
    type Input = [Cfg::F];
    type Output = Cfg::F;
    type Parameters = Cfg;

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        // WARNING: this config should be checked and not used in production as is
        Ok(Cfg::init::<N>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        Cfg::H::evaluate(parameters, input)
    }
}

impl<Cfg: Init> TwoToOneCRHScheme for NTo1CRH<Cfg, 2> {
    type Input = Cfg::F;

    type Output = Cfg::F;

    type Parameters = Cfg;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(Cfg::init::<2>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Cfg::H::evaluate(parameters, [*left_input.borrow(), *right_input.borrow()])
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Cfg::H::evaluate(parameters, [*left_input.borrow(), *right_input.borrow()])
    }
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::{
        CRHScheme, CRHSchemeGadget, poseidon::constraints::CRHParametersVar,
    };
    use ark_ff::UniformRand;
    use ark_grumpkin::{Projective, constraints::GVar};
    use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;

    use super::*;
    use crate::{
        datastructures::keypair::{KeyPair, PublicKey, constraints::PublicKeyVar},
        primitives::crh::{PublicKeyCRH, constraints::PublicKeyVarCRH},
    };

    #[test]
    pub fn test_public_key_crh() {
        let mut rng = thread_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pp = poseidon_canonical_config();
        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();

        for i in 0..20 {
            let key = if i == 0 {
                Projective::default() // zero point
            } else {
                Projective::rand(&mut rng)
            };
            let public_key = PublicKey { key };
            let public_key_var =
                PublicKeyVar::<Projective, GVar>::new_witness(cs.clone(), || Ok(public_key))
                    .unwrap();

            let res1 = PublicKeyCRH::<PoseidonConfig<_>, _>::evaluate(&pp, public_key).unwrap();
            let res2 = PublicKeyVarCRH::<PoseidonConfig<_>, Projective, GVar>::evaluate(
                &pp_var,
                &public_key_var,
            )
            .unwrap();

            assert_eq!(res1, res2.value().unwrap());

            // random public key
            let random_pk = KeyPair::<Projective>::new(&mut rng).pk;
            let random_pk_hash =
                PublicKeyCRH::<PoseidonConfig<_>, _>::evaluate(&pp, random_pk).unwrap();
            assert_ne!(random_pk_hash, res1);
        }
    }
}

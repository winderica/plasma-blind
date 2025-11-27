// Define the various CRH used in PlasmaFold
use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    Error,
    crh::{CRHScheme, poseidon::CRH},
    sponge::{
        Absorb,
        poseidon::{PoseidonConfig, find_poseidon_ark_and_mds},
    },
};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_std::rand::Rng;
use utils::initialize_poseidon_config;

use crate::datastructures::{
    block::{Block, BlockHash},
    keypair::PublicKey,
    noncemap::Nonce,
    shieldedtx::ShieldedTransaction,
    utxo::UTXO,
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

pub struct ShieldedTransactionCRH<C: CurveGroup> {
    _c: PhantomData<C>,
}

// hash(hash(pk), root shielded tx)
impl<C: CurveGroup<BaseField: PrimeField + Absorb>> CRHScheme for ShieldedTransactionCRH<C> {
    type Input = ShieldedTransaction<C>;
    type Output = C::BaseField;
    type Parameters = PoseidonConfig<C::BaseField>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(initialize_poseidon_config())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let res = input.borrow();
        let pk_hash = PublicKeyCRH::evaluate(parameters, res.from)?;
        Ok(CRH::evaluate(parameters, [pk_hash, res.shielded_tx])?)
    }
}

pub struct PublicKeyCRH<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> CRHScheme for PublicKeyCRH<C> {
    type Input = PublicKey<C>;
    type Output = C::BaseField;
    type Parameters = PoseidonConfig<C::BaseField>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(initialize_poseidon_config())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input: &PublicKey<C> = input.borrow();
        let point = input.key.into_affine();
        if point.is_zero() {
            Ok(CRH::evaluate(
                parameters,
                // flag for point is zero is true
                [C::BaseField::ZERO, C::BaseField::ZERO, C::BaseField::ONE],
            )?)
        } else {
            let (x, y) = point.xy().unwrap();
            // flag for point is zero is false
            Ok(CRH::evaluate(parameters, [x, y, C::BaseField::ZERO])?)
        }
    }
}

pub struct NonceCRH<F: PrimeField + Absorb> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for NonceCRH<F> {
    type Input = Nonce;
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let nonce: &Nonce = input.borrow();
        let input = F::from(nonce.0);
        CRH::evaluate(parameters, [input])
    }
}

pub struct UTXOCRH<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    _f: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> CRHScheme for UTXOCRH<C> {
    type Input = UTXO<C>;
    type Output = C::BaseField;
    type Parameters = PoseidonConfig<C::BaseField>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(initialize_poseidon_config())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let utxo: &UTXO<C> = input.borrow();
        let pk_point = utxo.pk.key.into_affine();
        let (x, y, iszero) = if pk_point.is_zero() {
            (C::BaseField::ZERO, C::BaseField::ZERO, C::BaseField::ONE)
        } else {
            (
                pk_point.x().unwrap(),
                pk_point.y().unwrap(),
                C::BaseField::from(pk_point.is_zero()),
            )
        };
        let input = [
            C::BaseField::from(utxo.amount),
            C::BaseField::from(utxo.is_dummy),
            C::BaseField::from(utxo.salt),
            C::BaseField::from(utxo.index),
            x,
            y,
            iszero,
        ];
        CRH::evaluate(parameters, input)
    }
}

pub struct BlockCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for BlockCRH<F> {
    type Input = Block<F>;
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(initialize_poseidon_config())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let block = input.borrow();
        let input = [
            block.tx_tree_root,
            block.signer_tree_root,
            F::from(block.height as u64),
        ];
        CRH::evaluate(parameters, input)
    }
}

pub struct BlockTreeCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

// identity hash
impl<F: PrimeField + Absorb> CRHScheme for BlockTreeCRH<F> {
    type Input = BlockHash<F>;
    type Output = F;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let block_hash = input.borrow();
        Ok(*block_hash)
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

            let res1 = PublicKeyCRH::evaluate(&pp, public_key).unwrap();
            let res2 = PublicKeyVarCRH::evaluate(&pp_var, &public_key_var).unwrap();

            assert_eq!(res1, res2.value().unwrap());

            // random public key
            let random_pk = KeyPair::<Projective>::new(&mut rng).pk;
            let random_pk_hash = PublicKeyCRH::evaluate(&pp, random_pk).unwrap();
            assert_ne!(random_pk_hash, res1);
        }
    }
}

use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::{
            TwoToOneCRH,
            constraints::{CRHGadget, TwoToOneCRHGadget},
        },
    },
    merkle_tree::{Config, Path, constraints::PathVar},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    groups::CurveVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::One;

use crate::{
    config::{PlasmaBlindConfig, PlasmaBlindConfigVar},
    datastructures::{
        TX_IO_SIZE,
        keypair::{PublicKey, constraints::PublicKeyVar},
        nullifier::constraints::NullifierVar,
        shieldedtx::{
            ShieldedTransaction, ShieldedTransactionConfig,
            constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
        },
        transparenttx::{TransparentTransaction, constraints::TransparentTransactionVar},
        utxo::{
            constraints::UTXOVar,
            proof::{UTXOProof, constraints::UTXOProofVar},
        },
    },
    primitives::{
        crh::constraints::UTXOVarCRH,
        sparsemt::{SparseConfig, constraints::SparseConfigGadget},
    },
};

#[derive(Clone)]
pub struct TransactionValidityCircuit<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    null_sk: C::BaseField, // user secret for nullifier computation
    null_pk: C::BaseField, // hash of user's secret, which is registered on the L1
    pk: PublicKey<C>,      // user public key
    transparent_tx: TransparentTransaction<C>, // transparent transaction
    shielded_tx: ShieldedTransaction<C>, // shielded transaction (root of tree built from
    // transparent tx)
    input_utxos_proofs: Vec<UTXOProof<C>>, // proof of existence of input
    // utxos
    plasma_blind_config: PlasmaBlindConfig<C>,
    _m: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    TransactionValidityCircuit<C, CVar>
{
    pub fn new(
        null_sk: C::BaseField, // user secret for nullifier computation
        null_pk: C::BaseField, // hash of user's secret, which is registered on the L1
        pk: PublicKey<C>,      // user public key
        transparent_tx: TransparentTransaction<C>, // transparent transaction
        shielded_tx: ShieldedTransaction<C>, // shielded transaction (root of tree built from
        // transparent tx)
        input_utxos_proofs: Vec<UTXOProof<C>>, // proof of existence of input
        // utxos
        plasma_blind_config: PlasmaBlindConfig<C>,
    ) -> Self {
        TransactionValidityCircuit {
            null_sk,
            null_pk,
            pk,
            transparent_tx,
            shielded_tx,
            input_utxos_proofs,
            plasma_blind_config,
            _m: PhantomData,
        }
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    ConstraintSynthesizer<C::BaseField> for TransactionValidityCircuit<C, CVar>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let null_sk = FpVar::new_witness(cs.clone(), || Ok(self.null_sk))?;
        let null_pk = FpVar::new_input(cs.clone(), || Ok(self.null_pk))?;
        let pk = PublicKeyVar::new_input(cs.clone(), || Ok(self.pk))?;
        let transparent_tx = TransparentTransactionVar::<_, CVar>::new_witness(cs.clone(), || {
            Ok(self.transparent_tx.clone())
        })?;
        let shielded_tx =
            ShieldedTransactionVar::<_>::new_input(cs.clone(), || Ok(self.shielded_tx)).unwrap();

        let input_utxos_proofs =
            Vec::<UTXOProofVar<_, _>>::new_witness(cs.clone(), || Ok(self.input_utxos_proofs))?;

        let plasma_blind_config = PlasmaBlindConfigVar::new_variable(
            cs.clone(),
            || Ok(self.plasma_blind_config),
            AllocationMode::Constant,
        )?;

        let null_pk_computed =
            CRHGadget::evaluate(&plasma_blind_config.poseidon_config, &[null_sk.clone()])?;
        null_pk_computed.enforce_equal(&null_pk)?;

        // checks transparent tx inputs sum up to outputs
        transparent_tx
            .inputs
            .iter()
            .map(|i| &i.amount)
            .sum::<FpVar<C::BaseField>>()
            .enforce_equal(
                &transparent_tx
                    .outputs
                    .iter()
                    .map(|i| &i.amount)
                    .sum::<FpVar<C::BaseField>>(),
            )?;

        for i in 0..TX_IO_SIZE {
            transparent_tx.inputs[i]
                .pk
                .conditional_enforce_equal(&pk, &!transparent_tx.inputs[i].amount.is_zero()?)?;

            transparent_tx.inputs[i].is_valid(
                &null_sk,
                &transparent_tx.inputs[i].pk,
                &shielded_tx.input_nullifiers[i],
                &input_utxos_proofs[i],
                &plasma_blind_config,
            )?;

            shielded_tx.output_utxo_commitments[i].conditional_enforce_equal(
                &UTXOVarCRH::evaluate(
                    &plasma_blind_config.utxo_crh_config,
                    &transparent_tx.outputs[i],
                )?,
                &!transparent_tx.outputs[i].amount.is_zero()?,
            )?;
        }

        // TODO: move to agg
        // plasma_blind_config
        //     .utxo_tree
        //     .build_root(&shielded_tx.output_utxo_commitments)?;

        Ok(())
    }
}

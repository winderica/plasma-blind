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
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{
        FieldVar,
        fp::{AllocatedFp, FpVar},
    },
    groups::CurveVar,
    prelude::Boolean,
};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable},
    lc, lc_diff,
};
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
pub struct TransactionValidityCircuit<F: PrimeField> {
    null_sk: F,                                // user secret for nullifier computation
    null_pk: F, // hash of user's secret, which is registered on the L1
    transparent_tx: TransparentTransaction<F>, // transparent transaction
    shielded_tx: ShieldedTransaction<F>, // shielded transaction (root of tree built from
    // transparent tx)
    block_tree_root: F,
    input_utxos_proofs: Vec<UTXOProof<F>>, // proof of existence of input
    // utxos
    plasma_blind_config: PlasmaBlindConfig<F>,
}

impl<F: PrimeField> TransactionValidityCircuit<F> {
    pub fn new(
        null_sk: F,                                // user secret for nullifier computation
        null_pk: F, // hash of user's secret, which is registered on the L1
        transparent_tx: TransparentTransaction<F>, // transparent transaction
        shielded_tx: ShieldedTransaction<F>, // shielded transaction (root of tree built from
        // transparent tx)
        block_tree_root: F,
        input_utxos_proofs: Vec<UTXOProof<F>>, // proof of existence of input
        // utxos
        plasma_blind_config: PlasmaBlindConfig<F>,
    ) -> Self {
        TransactionValidityCircuit {
            null_sk,
            null_pk,
            transparent_tx,
            shielded_tx,
            block_tree_root,
            input_utxos_proofs,
            plasma_blind_config,
        }
    }
}

impl<F: PrimeField + Absorb> ConstraintSynthesizer<F> for TransactionValidityCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let null_sk = FpVar::new_witness(cs.clone(), || Ok(self.null_sk))?;
        let null_pk = FpVar::new_input(cs.clone(), || Ok(self.null_pk))?;
        let transparent_tx =
            TransparentTransactionVar::new_witness(cs.clone(), || Ok(self.transparent_tx.clone()))?;
        let shielded_tx =
            ShieldedTransactionVar::<_>::new_input(cs.clone(), || Ok(self.shielded_tx))?;
        let block_tree_root = FpVar::new_input(cs.clone(), || Ok(self.block_tree_root))?;

        let input_utxos_proofs =
            Vec::<UTXOProofVar<_>>::new_witness(cs.clone(), || Ok(self.input_utxos_proofs))?;

        let plasma_blind_config = PlasmaBlindConfigVar::new_variable(
            cs.clone(),
            || Ok(self.plasma_blind_config),
            AllocationMode::Constant,
        )?;

        let null_pk_computed =
            CRHGadget::evaluate(&plasma_blind_config.poseidon_config, &[null_sk.clone()])?;
        null_pk_computed.enforce_equal(&null_pk)?;

        // checks transparent tx inputs sum up to outputs
        transparent_tx.enforce_valid(&null_pk)?;

        for i in 0..TX_IO_SIZE {
            transparent_tx.inputs[i].is_valid(
                &null_sk,
                &shielded_tx.input_nullifiers[i],
                &transparent_tx.inputs_info[i],
                &input_utxos_proofs[i],
                &block_tree_root,
                &plasma_blind_config,
            )?;

            shielded_tx.output_utxo_commitments[i].enforce_equal(
                &transparent_tx.outputs[i].is_dummy.select(
                    &FpVar::zero(),
                    &UTXOVarCRH::evaluate(
                        &plasma_blind_config.utxo_crh_config,
                        &transparent_tx.outputs[i],
                    )?,
                )?,
            )?;
        }

        Ok(())
    }
}

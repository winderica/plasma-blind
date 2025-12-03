use std::marker::PhantomData;

use crate::config::{PlasmaBlindConfig, PlasmaBlindConfigVar};
use crate::datastructures::transparenttx::constraints::TransparentTransactionVar;
use crate::datastructures::utxo::proof::{UTXOProof, constraints::UTXOProofVar};
use crate::datastructures::{
    TX_IO_SIZE,
    keypair::{PublicKey, constraints::PublicKeyVar},
    shieldedtx::{
        ShieldedTransaction, ShieldedTransactionConfig,
        constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
    },
    transparenttx::TransparentTransaction,
    utxo::constraints::UTXOVar,
};
use crate::primitives::sparsemt::{SparseConfig, constraints::SparseConfigGadget};
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
use ark_r1cs_std::prelude::Boolean;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::One;

#[derive(Clone)]
pub struct TransactionValidityCircuit<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    TC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // transaction tree config
    TCG: SparseConfigGadget<
            TC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = ShieldedTransactionVar<C, CVar>,
        >,
    SC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // signer tree config
    SCG: SparseConfigGadget<
            SC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = PublicKeyVar<C, CVar>,
        >,
> {
    null_sk: C::BaseField, // user secret for nullifier computation
    null_pk: C::BaseField, // hash of user's secret, which is registered on the L1
    pk: PublicKey<C>,      // user public key
    transparent_tx: TransparentTransaction<C>, // transparent transaction
    shielded_tx: ShieldedTransaction<C>, // shielded transaction (root of tree built from
    // transparent tx)
    shielded_tx_outputs: Vec<<ShieldedTransactionConfig<C> as Config>::Leaf>, // utxo leaves of shielded_tx
    shielded_tx_outputs_proofs: Vec<Path<ShieldedTransactionConfig<C>>>, // proofs that output utxo is leaf of current shielded transaction
    input_utxos_proofs: Vec<UTXOProof<C, TC, SC>>, // proof of existence of input
    // utxos
    plasma_blind_config: PlasmaBlindConfig<C, TC, SC>,
    _m: PhantomData<(CVar, SCG, TCG)>,
}

impl<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    TC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>> + Clone, // transaction tree config
    TCG: SparseConfigGadget<
            TC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = ShieldedTransactionVar<C, CVar>,
        >,
    SC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>> + Clone, // signer tree config
    SCG: SparseConfigGadget<
            SC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = PublicKeyVar<C, CVar>,
        >,
> TransactionValidityCircuit<C, CVar, TC, TCG, SC, SCG>
{
    pub fn new(
        null_sk: C::BaseField, // user secret for nullifier computation
        null_pk: C::BaseField, // hash of user's secret, which is registered on the L1
        pk: PublicKey<C>,      // user public key
        transparent_tx: TransparentTransaction<C>, // transparent transaction
        shielded_tx: ShieldedTransaction<C>, // shielded transaction (root of tree built from
        // transparent tx)
        shielded_tx_outputs: Vec<<ShieldedTransactionConfig<C> as Config>::Leaf>, // utxo leaves of shielded_tx
        shielded_tx_outputs_proofs: Vec<Path<ShieldedTransactionConfig<C>>>, // proofs that output utxo is leaf of current shielded transaction
        input_utxos_proofs: Vec<UTXOProof<C, TC, SC>>, // proof of existence of input
        // utxos
        plasma_blind_config: PlasmaBlindConfig<C, TC, SC>,
    ) -> Self {
        TransactionValidityCircuit {
            null_sk,
            null_pk,
            pk,
            transparent_tx,
            shielded_tx,
            shielded_tx_outputs,
            shielded_tx_outputs_proofs,
            input_utxos_proofs,
            plasma_blind_config,
            _m: PhantomData::<(CVar, SCG, TCG)>,
        }
    }
}

impl<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    TC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>> + Clone, // transaction tree config
    TCG: SparseConfigGadget<
            TC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = ShieldedTransactionVar<C, CVar>,
        >,
    SC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>> + Clone, // signer tree config
    SCG: SparseConfigGadget<
            SC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = PublicKeyVar<C, CVar>,
        >,
> ConstraintSynthesizer<C::BaseField> for TransactionValidityCircuit<C, CVar, TC, TCG, SC, SCG>
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
            ShieldedTransactionVar::<_, CVar>::new_input(cs.clone(), || Ok(self.shielded_tx))
                .unwrap();

        // define input witness values
        let shielded_tx_outputs = Vec::<UTXOVar<_, CVar>>::new_witness(cs.clone(), || {
            Ok(self.shielded_tx_outputs.clone())
        })?;
        let shielded_tx_outputs_proofs = Vec::<
            PathVar<_, _, ShieldedTransactionConfigGadget<_, CVar>>,
        >::new_witness(cs.clone(), || {
            Ok(self.shielded_tx_outputs_proofs)
        })
        .unwrap();
        let input_utxos_proofs =
            Vec::<UTXOProofVar<_, CVar, _, TCG, _, SCG>>::new_witness(cs.clone(), || {
                Ok(self.input_utxos_proofs)
            })?;

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

        for input_utxo_proof in input_utxos_proofs {
            input_utxo_proof.is_valid(&null_sk, pk.clone(), &plasma_blind_config)?;
        }

        // initialize variables to ensure that output utxos have a strictly increasing index starting
        // at TX_IO_SIZE
        let one = FpVar::new_constant(cs.clone(), C::BaseField::one())?;
        let mut index_output_utxo =
            FpVar::new_constant(cs.clone(), C::BaseField::from((TX_IO_SIZE) as u64))?;

        for (shielded_tx_inclusion_proof, output_utxo) in
            shielded_tx_outputs_proofs.iter().zip(shielded_tx_outputs)
        {
            // ensure that utxo indexes are correct
            output_utxo.index.enforce_equal(&index_output_utxo)?;
            let is_in_tx = shielded_tx_inclusion_proof.verify_membership(
                &plasma_blind_config.shielded_tx_leaf_config,
                &plasma_blind_config.shielded_tx_two_to_one_config,
                &shielded_tx.shielded_tx,
                &output_utxo,
            )?;

            is_in_tx.enforce_equal(&Boolean::Constant(true))?;
            index_output_utxo += one.clone();
        }

        Ok(())
    }
}

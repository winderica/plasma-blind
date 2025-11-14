use core::{
    datastructures::{
        block::constraints::BlockVar,
        keypair::constraints::PublicKeyVar,
        shieldedtx::{
            constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
            ShieldedTransaction, ShieldedTransactionConfig,
        },
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
        txtree::{constraints::TransactionTreeConfigGadget, TransactionTreeConfig},
        utxo::constraints::UTXOVar,
    },
    primitives::{
        accumulator::constraints::Accumulator,
        crh::constraints::{BlockVarCRH, PublicKeyVarCRH},
        sparsemt::constraints::MerkleSparseTreePathVar,
    },
};
use std::ops::Not;
use std::{cmp::Ordering, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::CRHParametersVar, CRHSchemeGadget, TwoToOneCRHScheme,
        TwoToOneCRHSchemeGadget,
    },
    merkle_tree::constraints::{ConfigGadget, PathVar},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, groups::CurveVar, prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct UserCircuit<
    F: PrimeField + Absorb,
    C: CurveGroup,
    CVar: CurveVar<C, F>,
    H: TwoToOneCRHScheme,
    T: TwoToOneCRHSchemeGadget<H, F>,
    A: Accumulator<F, H, T>,
    const N_TX_PER_FOLD_STEP: usize,
> {
    _a: PhantomData<A>,
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
    acc_pp: T::ParametersVar, // public parameters for the accumulator might not be poseidon
    pp: CRHParametersVar<F>,
}

// Process transaction-wise. For each tx:
// - get block content: (tx_tree, signer_tree) := block (not using the nullifier tree?) (ok)
// - get shielded tx content: shielded transaction, index in tree and utxo openings (ok)
// - show that shielded transaction is in tx tree (ok)
// - show that signer bit for committed_tx_root has been set to 1 (ok)
// - user is sender if transacation's pk is his pk (ok)
// - for each utxo:
//      - a utxo is valid when it is supposed to be opened and is in the shielded tx (ok)
//      - if user is sender, he should process all utxos (ok)
//      - if user is receiver and utxo is valid, increase balance (ok)
//      - if user is sender and utxo is valid, decrease balance (ok)
// - accumulate block hash
#[derive(Clone, Debug)]
pub struct UserAuxVar<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>> {
    pub block: BlockVar<F>,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub shielded_tx: ShieldedTransactionVar<C, CVar>,
    // index of transaction within transaction tree
    pub tx_index: FpVar<C::BaseField>,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXOVar<C, CVar>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<
        PathVar<
            ShieldedTransactionConfig<C>,
            C::BaseField,
            ShieldedTransactionConfigGadget<C, CVar>,
        >,
    >,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: Vec<Boolean<C::BaseField>>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof:
        MerkleSparseTreePathVar<TransactionTreeConfig<C>, F, TransactionTreeConfigGadget<C, CVar>>,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof:
        MerkleSparseTreePathVar<SignerTreeConfig<C>, F, SignerTreeConfigGadget<C, CVar>>,
    pub pk: PublicKeyVar<C, CVar>,
}

impl<
        F: PrimeField + Absorb,
        C: CurveGroup<BaseField = F>,
        CVar: CurveVar<C, F>,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, F>,
        A: Accumulator<F, H, T>,
        const N_TX_PER_FOLD_STEP: usize,
    > UserCircuit<F, C, CVar, H, T, A, N_TX_PER_FOLD_STEP>
{
    pub fn update_balance(
        &self,
        cs: ConstraintSystemRef<F>,
        z_i: Vec<FpVar<F>>,
        aux: UserAuxVar<F, C, CVar>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let (balance, nonce, pk_hash, acc, block_hash, block_number, processed_tx_index) = (
            z_i[0].clone(),
            z_i[1].clone(),
            z_i[2].clone(),
            z_i[3].clone(),
            z_i[4].clone(),
            z_i[5].clone(),
            z_i[6].clone(),
        );

        // ensure correct pk is provided in aux inputs
        let computed_pk_hash = PublicKeyVarCRH::evaluate(&self.pp, &aux.pk)?;
        computed_pk_hash.enforce_equal(&pk_hash)?;

        // compute block hash and update accumulator value
        let next_block_hash = BlockVarCRH::evaluate(&self.pp, &aux.block)?;
        let next_acc = A::update(&self.acc_pp, &acc, &block_hash)?;

        // ensure the current processed block number is equal or greater than the previous block
        let next_block_number = aux.block.height;
        let _ = &block_number.enforce_cmp(&next_block_number, Ordering::Less, true)?;

        // ensure that the processed tx has greater tx index (when processing same block)
        let next_tx_index = aux.tx_index;
        let is_same_block = next_block_hash.is_eq(&block_hash)?;
        let is_higher_tx_index =
            &next_tx_index.is_cmp(&processed_tx_index, Ordering::Greater, false)?;
        is_higher_tx_index.conditional_enforce_equal(&Boolean::Constant(true), &is_same_block)?;

        // check that shielded tx is in tx tree
        aux.shielded_tx_inclusion_proof
            .check_membership_with_index(
                &self.pp,
                &self.pp,
                &aux.block.tx_tree_root,
                &aux.shielded_tx,
                &next_tx_index,
            )?;

        // check that the signer bit is 1 for the corresponding transaction (i.e. pk is included)
        aux.signer_pk_inclusion_proof.check_membership(
            &self.pp,
            &self.pp,
            &aux.block.signer_tree_root,
            &aux.shielded_tx.from,
        )?;

        // validity of input utxos is already checked by the transaction validity circuit and the
        // aggregator, so we only need to process the output utxos?
        // note that the transaction validity circuit ensures that sum(inputs) == sum(outputs)
        let is_sender = aux.pk.key.is_eq(&aux.shielded_tx.from.key)?;
        let next_nonce = nonce + &is_sender.clone().into();
        let mut next_balance = balance;

        // if the user is the sender, he should provide data for all the output utxos
        // if the user is not the sender, he should provide data for the output utxos sent to him
        for ((is_opened, utxo), utxo_proof) in aux
            .openings_mask
            .iter()
            .zip(aux.shielded_tx_utxos)
            .zip(aux.shielded_tx_utxos_proofs)
        {
            let is_in_tree = utxo_proof.verify_membership(
                &self.pp,
                &self.pp,
                &aux.shielded_tx.shielded_tx,
                &utxo,
            )?;

            let is_valid_utxo = is_opened & is_in_tree;
            Boolean::Constant(true).conditional_enforce_equal(&is_valid_utxo, &is_sender)?;

            let is_receiver = utxo.pk.key.is_eq(&aux.pk.key)?;
            let increase_balance = is_receiver.clone() & is_valid_utxo.clone();
            let decrease_balance = is_sender.clone() & is_valid_utxo;
            next_balance += utxo.amount.clone() * &increase_balance.into();
            next_balance -= utxo.amount * &decrease_balance.into();
        }
        Ok(vec![
            next_balance,
            next_nonce,
            pk_hash,
            next_acc,
            next_block_hash,
            next_block_number,
            next_tx_index,
        ])
    }
}

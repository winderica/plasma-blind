use core::{
    datastructures::{
        block::constraints::BlockVar,
        keypair::constraints::PublicKeyVar,
        shieldedtx::{
            constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
            ShieldedTransactionConfig,
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
    alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, groups::CurveVar, select::CondSelectGadget,
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
// - get block content: (tx_tree, signer_tree) := block (not using the nullifier tree?)
// - get committed tx content: committed_tx_root and utxo_openings
// - show that committed_tx_root is in tx_tree
// - show that signer bit for committed_tx_root has been set to 1
// if this is receiving one or more utxo from this transaction:
//      - prove that user knows opening of a utxo in this committed transaction
//      - utxo "to" field corresponds to user's pk
//      - increase user's balance
// if this is processing a send transaction:
//      - transaction "from" field is user's pk
//      - decrease the user's balance
//      - increase user's nonce by one
// - accumulate block hash
#[derive(Clone, Debug)]
pub struct UserAuxVar<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>> {
    pub block: BlockVar<F>,
    // shielded tx comes with its index in the transaction tree which was built by the aggregator
    pub shielded_tx: (
        <ShieldedTransactionVar<C, CVar> as ConfigGadget<
            ShieldedTransactionConfig<C>,
            C::BaseField,
        >>::InnerDigest,
        FpVar<C::BaseField>,
    ),
    // input utxos in shielded tx
    pub shielded_tx_inputs: Vec<UTXOVar<C, CVar>>,
    // output uxtos in shielded tx
    pub shielded_tx_outputs: Vec<UTXOVar<C, CVar>>,
    // openings for utxos
    pub shielded_tx_proof: Vec<
        PathVar<
            ShieldedTransactionConfig<C>,
            C::BaseField,
            ShieldedTransactionConfigGadget<C, CVar>,
        >,
    >,
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
        let (
            mut balance_t_plus_1,
            mut nonce_t_plus_1,
            pk_hash,
            mut acc_t_plus_1,
            mut prev_block_hash,
            mut prev_block_number,
            mut prev_processed_tx_index,
        ) = (
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
        let block_hash = BlockVarCRH::evaluate(&self.pp, &aux.block)?;
        acc_t_plus_1 = A::update(&self.acc_pp, &acc_t_plus_1, &block_hash)?;

        // ensure the current processed block number is equal or greater than the previous block
        let _ = &prev_block_number.enforce_cmp(&aux.block.height, Ordering::Less, true)?;

        // if prev_block_hash != currently_processed_block -> currently processed tx index should
        // be reset to 0
        let processing_same_block = block_hash.is_eq(&prev_block_hash)?;
        prev_processed_tx_index = CondSelectGadget::conditionally_select(
            &processing_same_block,
            &prev_processed_tx_index,
            &FpVar::new_constant(cs.clone(), F::zero())?,
        )?;

        let (shielded_tx, shielded_tx_idx) = aux.shielded_tx;

        // prev tx index should be strictly lower than the currently processed transaction
        let prev_tx_index_is_lower =
            &prev_processed_tx_index.is_cmp(&shielded_tx_idx, Ordering::Less, false)?;

        // check that tx is in tx tree
        // if the tx is a dummy transaction, this check is not enforced
        aux.shielded_tx_inclusion_proof
            .check_membership_with_index(
                &self.pp,
                &self.pp,
                &aux.block.tx_tree_root,
                &shielded_tx,
                &shielded_tx_idx,
            )?;

        // show that the committed tx is in the tx tree
        todo!()
    }
}

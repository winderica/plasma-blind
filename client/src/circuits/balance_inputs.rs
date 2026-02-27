use crate::circuits::OpeningsMaskVar;
use nmerkle_trees::sparse::NArySparsePath;
use plasmablind_core::datastructures::{
    block::BlockMetadata,
    blocktree::BLOCK_TREE_ARITY,
    signerlist::{SignerTreeConfig, SparseNArySignerTreeConfig},
    txtree::{SparseNAryTransactionTreeConfig, TransactionTreeConfig, TRANSACTION_TREE_ARITY},
    utxo::UTXO,
};

use ark_crypto_primitives::sponge::Absorb;

use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use nmerkle_trees::sparse::constraints::NArySparsePathVar;
use plasmablind_core::datastructures::{
    block::constraints::BlockMetadataVar,
    signerlist::{
        constraints::{SignerTreeConfigGadget, SparseNArySignerTreeConfigGadget},
        SIGNER_TREE_ARITY,
    },
    txtree::constraints::{SparseNAryTransactionTreeConfigGadget, TransactionTreeConfigGadget},
    utxo::constraints::UTXOVar,
};
use sonobe_fs::FoldingSchemeDef;
use std::borrow::Borrow;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMask = Vec<bool>;

pub struct BalanceAux<FS1: FoldingSchemeDef<TranscriptField: Absorb>> {
    pub block: BlockMetadata<FS1::TranscriptField>,
    pub from: FS1::TranscriptField,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub utxo_tree_root: FS1::TranscriptField,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXO<FS1::TranscriptField>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<(Vec<FS1::TranscriptField>, FS1::TranscriptField)>,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: Vec<bool>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof: NArySparsePath<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<FS1::TranscriptField>,
        SparseNAryTransactionTreeConfig<FS1::TranscriptField>,
    >,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof: NArySparsePath<
        BLOCK_TREE_ARITY,
        SignerTreeConfig<FS1::TranscriptField>,
        SparseNArySignerTreeConfig<FS1::TranscriptField>,
    >,
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
pub struct BalanceAuxVar<FS1: FoldingSchemeDef<TranscriptField: Absorb>> {
    pub block: BlockMetadataVar<FS1::TranscriptField>,
    pub from: FpVar<FS1::TranscriptField>,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub utxo_tree_root: FpVar<FS1::TranscriptField>,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXOVar<FS1::TranscriptField>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<(
        Vec<FpVar<FS1::TranscriptField>>,
        FpVar<FS1::TranscriptField>,
    )>,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: OpeningsMaskVar<FS1::TranscriptField>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof: NArySparsePathVar<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<FS1::TranscriptField>,
        TransactionTreeConfigGadget<FS1::TranscriptField>,
        FS1::TranscriptField,
        SparseNAryTransactionTreeConfig<FS1::TranscriptField>,
        SparseNAryTransactionTreeConfigGadget<FS1::TranscriptField>,
    >,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof: NArySparsePathVar<
        SIGNER_TREE_ARITY,
        SignerTreeConfig<FS1::TranscriptField>,
        SignerTreeConfigGadget<FS1::TranscriptField>,
        FS1::TranscriptField,
        SparseNArySignerTreeConfig<FS1::TranscriptField>,
        SparseNArySignerTreeConfigGadget<FS1::TranscriptField>,
    >,
}

impl<FS1: FoldingSchemeDef<TranscriptField: Absorb>> AllocVar<BalanceAux<FS1>, FS1::TranscriptField>
    for BalanceAuxVar<FS1>
{
    fn new_variable<T: Borrow<BalanceAux<FS1>>>(
        cs: impl Into<Namespace<FS1::TranscriptField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let t = f()?;
        let user_aux = t.borrow();
        let block =
            BlockMetadataVar::new_variable(cs.clone(), || Ok(user_aux.block.clone()), mode)?;
        let from = FpVar::new_variable(cs.clone(), || Ok(user_aux.from), mode)?;
        let utxo_tree_root = FpVar::new_variable(cs.clone(), || Ok(user_aux.utxo_tree_root), mode)?;
        let shielded_tx_utxos = Vec::<UTXOVar<_>>::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx_utxos.clone()),
            mode,
        )?;
        let shielded_tx_utxos_proofs = user_aux
            .shielded_tx_utxos_proofs
            .iter()
            .map(|i| {
                Ok((
                    Vec::new_variable(cs.clone(), || Ok(&i.0[..]), mode)?,
                    FpVar::new_variable(cs.clone(), || Ok(&i.1), mode)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let openings_mask =
            Vec::new_variable(cs.clone(), || Ok(user_aux.openings_mask.clone()), mode)?;
        let shielded_tx_inclusion_proof = NArySparsePathVar::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx_inclusion_proof.clone()),
            mode,
        )?;
        let signer_pk_inclusion_proof = NArySparsePathVar::new_variable(
            cs.clone(),
            || Ok(user_aux.signer_pk_inclusion_proof.clone()),
            mode,
        )?;
        Ok(BalanceAuxVar {
            block,
            from,
            utxo_tree_root,
            shielded_tx_utxos,
            shielded_tx_utxos_proofs,
            openings_mask,
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof,
        })
    }
}

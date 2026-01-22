use ark_crypto_primitives::{crh::CRHSchemeGadget, sponge::Absorb};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    groups::CurveVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::SynthesisError;
use nmerkle_trees::sparse::constraints::NArySparsePathVar;
use sonobe_primitives::{algebra::ops::bits::ToBitsGadgetExt, transcripts::Absorbable};

use super::UTXOProof;
use crate::{
    config::PlasmaBlindConfigVar,
    datastructures::{
        block::constraints::BlockMetadataVar,
        blocktree::{
            BLOCK_TREE_ARITY, BlockTreeConfig, SparseNAryBlockTreeConfig,
            constraints::{BlockTreeConfigGadget, SparseNAryBlockTreeConfigGadget},
        },
        nullifier::constraints::NullifierVar,
        shieldedtx::SHIELDED_TX_TREE_HEIGHT,
        signerlist::{
            SIGNER_TREE_ARITY, SignerTreeConfig, SparseNArySignerTreeConfig,
            constraints::{SignerTreeConfigGadget, SparseNArySignerTreeConfigGadget},
        },
        txtree::{
            SparseNAryTransactionTreeConfig, TRANSACTION_TREE_ARITY, TransactionTreeConfig,
            constraints::{SparseNAryTransactionTreeConfigGadget, TransactionTreeConfigGadget},
        },
        utxo::constraints::{UTXOInfoVar, UTXOVar},
    },
    primitives::crh::constraints::UTXOVarCRH,
};

pub struct UTXOProofVar<F: PrimeField + Absorb + Absorbable> {
    block: BlockMetadataVar<F>,
    utxo_inclusion_proof: Vec<FpVar<F>>,
    signer_inclusion_proof: NArySparsePathVar<
        SIGNER_TREE_ARITY,
        SignerTreeConfig<F>,
        SignerTreeConfigGadget<F>,
        F,
        SparseNArySignerTreeConfig<F>,
        SparseNArySignerTreeConfigGadget<F>,
    >,
    tx_inclusion_proof: NArySparsePathVar<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<F>,
        TransactionTreeConfigGadget<F>,
        F,
        SparseNAryTransactionTreeConfig<F>,
        SparseNAryTransactionTreeConfigGadget<F>,
    >,
    block_inclusion_proof: NArySparsePathVar<
        BLOCK_TREE_ARITY,
        BlockTreeConfig<F>,
        BlockTreeConfigGadget<F>,
        F,
        SparseNAryBlockTreeConfig<F>,
        SparseNAryBlockTreeConfigGadget<F>,
    >,
}

impl<F: PrimeField + Absorb + Absorbable> AllocVar<UTXOProof<F>, F> for UTXOProofVar<F> {
    fn new_variable<T: std::borrow::Borrow<UTXOProof<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let res = f()?;
        let utxo_proof = res.borrow();

        let block = BlockMetadataVar::new_variable(cs.clone(), || Ok(&utxo_proof.block), mode)?;

        let utxo_inclusion_proof =
            Vec::new_variable(cs.clone(), || Ok(&utxo_proof.utxo_path[..]), mode)?;

        let signer_inclusion_proof = NArySparsePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.signer_path.clone()),
            mode,
        )?;

        let tx_inclusion_proof =
            NArySparsePathVar::new_variable(cs.clone(), || Ok(utxo_proof.tx_path.clone()), mode)?;

        let block_inclusion_proof = NArySparsePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.block_path.clone()),
            mode,
        )?;

        Ok(UTXOProofVar {
            block,
            utxo_inclusion_proof,
            signer_inclusion_proof,
            tx_inclusion_proof,
            block_inclusion_proof,
        })
    }
}

impl<F: PrimeField + Absorb + Absorbable> UTXOVar<F> {
    // An input utxo is valid if:
    // 1. it exists in a shielded transaction tx
    // 2. the shielded transaction tx exists in a transation tree T^{tx} with root r^{tx}
    // 3. the transaction tree T has been signed by the sender s
    // 4. the transaction tree exists in a block B
    // 5. the block B exists in a block tree T^{block} with root r^{block}
    // 6. nullifier is correct
    // 7. the user is the utxo owner (already checked)
    // 8.
    pub fn is_valid(
        &self,
        sk: &FpVar<F>,
        nullifier: &NullifierVar<F>,
        info: &UTXOInfoVar<F>,
        proof: &UTXOProofVar<F>,
        block_tree_root: &FpVar<F>,
        plasma_blind_config: &PlasmaBlindConfigVar<F>,
    ) -> Result<(), SynthesisError> {
        // checks only apply when the utxo is not zero
        let is_not_dummy = !&self.is_dummy;

        // 1. utxo exists in a shielded transaction tx
        let utxo_tree_root = plasma_blind_config.utxo_tree.recover_root(
            &UTXOVarCRH::evaluate(&plasma_blind_config.utxo_crh_config, self)?,
            &info.utxo_index.to_n_bits_le(SHIELDED_TX_TREE_HEIGHT - 1)?,
            &proof.utxo_inclusion_proof,
        )?;

        // 2. the shielded transaction tx exists in a transation tree T^{tx} with root r^{tx}
        proof
            .tx_inclusion_proof
            .conditionally_calculate_root(
                &(),
                &plasma_blind_config.tx_tree_n_to_one_config,
                &utxo_tree_root,
                &is_not_dummy,
            )?
            .conditional_enforce_equal(&proof.block.tx_tree_root, &is_not_dummy)?;
        proof
            .tx_inclusion_proof
            .index
            .enforce_equal(&info.tx_index)?;

        // 3. the transaction tree T has been signed by the sender s
        proof
            .signer_inclusion_proof
            .conditionally_calculate_root(
                &(),
                &plasma_blind_config.signer_tree_n_to_one_config,
                &info.from,
                &is_not_dummy,
            )?
            .conditional_enforce_equal(&proof.block.signer_tree_root, &is_not_dummy)?;
        proof
            .signer_inclusion_proof
            .index
            .enforce_equal(&info.tx_index)?;

        // 4. block is contained within the block tree
        proof
            .block_inclusion_proof
            .conditionally_calculate_root(
                &plasma_blind_config.block_tree_leaf_config,
                &plasma_blind_config.block_tree_n_to_one_config,
                &proof.block,
                &is_not_dummy,
            )?
            .conditional_enforce_equal(&block_tree_root, &is_not_dummy)?;
        proof
            .block_inclusion_proof
            .index
            .enforce_equal(&info.block_height)?;

        // 5. nullifier computation is correct
        nullifier.value.enforce_equal(&is_not_dummy.select(
            &NullifierVar::new(&plasma_blind_config.poseidon_config, sk, info)?.value,
            &FpVar::zero(),
        )?)?;

        Ok(())
    }
}

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::{TwoToOneCRH, constraints::TwoToOneCRHGadget},
    },
    merkle_tree::{
        Config,
        constraints::{ConfigGadget, PathVar},
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar, alloc::AllocVar, eq::EqGadget, fields::{FieldVar, fp::FpVar}, groups::CurveVar, prelude::Boolean
};
use ark_relations::gr1cs::SynthesisError;

use super::UTXOProof;
use crate::{
    config::PlasmaBlindConfigVar,
    datastructures::{
        block::constraints::BlockVar,
        blocktree::{BlockTreeConfig, constraints::BlockTreeConfigGadget},
        keypair::constraints::PublicKeyVar,
        nullifier::constraints::NullifierVar,
        shieldedtx::{
            ShieldedTransactionConfig,
            constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
        },
        utxo::constraints::UTXOVar,
    },
    primitives::{
        crh::constraints::{BlockVarCRH, UTXOVarCRH},
        sparsemt::{SparseConfig, constraints::SparseConfigGadget},
    },
};

pub struct UTXOProofVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    block: BlockVar<C::BaseField>,
    utxo_tree_root: FpVar<C::BaseField>,
    utxo_inclusion_proof: (Vec<FpVar<C::BaseField>>, FpVar<C::BaseField>),
    signer: PublicKeyVar<C, CVar>,
    signer_inclusion_proof: (Vec<FpVar<C::BaseField>>, FpVar<C::BaseField>),
    tx_inclusion_proof: (Vec<FpVar<C::BaseField>>, FpVar<C::BaseField>),
    block_tree_root: FpVar<C::BaseField>,
    block_inclusion_proof: (Vec<FpVar<C::BaseField>>, FpVar<C::BaseField>),
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<UTXOProof<C>, C::BaseField> for UTXOProofVar<C, CVar>
{
    fn new_variable<T: std::borrow::Borrow<UTXOProof<C>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let res = f()?;
        let utxo_proof = res.borrow();

        let block = BlockVar::new_variable(cs.clone(), || Ok(&utxo_proof.block), mode)?;
        let signer = PublicKeyVar::new_variable(cs.clone(), || Ok(&utxo_proof.signer), mode)?;
        let utxo_tree_root =
            FpVar::new_variable(cs.clone(), || Ok(utxo_proof.utxo_tree_root), mode)?;

        let utxo_index = FpVar::new_variable(cs.clone(), || Ok(&utxo_proof.utxo_index), mode)?;
        let utxo_path = Vec::new_variable(cs.clone(), || Ok(&utxo_proof.utxo_path[..]), mode)?;
        let signer_path = Vec::new_variable(cs.clone(), || Ok(&utxo_proof.signer_path[..]), mode)?;
        let signer_index = FpVar::new_variable(cs.clone(), || Ok(utxo_proof.signer_index), mode)?;
        let tx_path = Vec::new_variable(cs.clone(), || Ok(&utxo_proof.tx_path[..]), mode)?;
        let tx_index = FpVar::new_variable(cs.clone(), || Ok(utxo_proof.tx_index), mode)?;

        let block_path = Vec::new_variable(cs.clone(), || Ok(utxo_proof.block_path.clone()), mode)?;
        let block_index = FpVar::new_variable(cs.clone(), || Ok(utxo_proof.block_index), mode)?;

        // note that nullifier and block tree root are public by default
        let block_tree_root = AllocVar::new_input(cs.clone(), || Ok(utxo_proof.block_tree_root))?;

        Ok(UTXOProofVar {
            block,
            signer,
            utxo_tree_root,
            utxo_inclusion_proof: (utxo_path, utxo_index),
            signer_inclusion_proof: (signer_path, signer_index),
            tx_inclusion_proof: (tx_path, tx_index),
            block_tree_root,
            block_inclusion_proof: (block_path, block_index),
        })
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    UTXOVar<C, CVar>
{
    // a utxo is valid if:
    // 1. it exists in a shielded transaction tx
    // 2. the shielded transaction tx exists in a transation tree T^{tx} with root r^{tx}
    // 3. the transaction tree T has been signed by the sender s
    // 4. the transaction tree exists in a block B
    // 5. the block B exists in a block tree T^{block} with root r^{block}
    // 6. nullifier is correct
    // 7. the user is the utxo owner
    // 8.
    pub fn is_valid(
        &self,
        sk: &FpVar<C::BaseField>,
        pk: &PublicKeyVar<C, CVar>,
        nullifier: &NullifierVar<C::BaseField>,
        proof: &UTXOProofVar<C, CVar>,
        plasma_blind_config: &PlasmaBlindConfigVar<C, CVar>,
    ) -> Result<(), SynthesisError> {
        // checks only apply when the utxo is not zero
        let is_not_zero = !self.amount.is_zero()?;

        // 1. utxo exists in a shielded transaction tx
        plasma_blind_config.utxo_tree.conditionally_check_index(
            &proof.utxo_tree_root,
            &UTXOVarCRH::evaluate(&plasma_blind_config.utxo_crh_config, self)?,
            &proof.utxo_inclusion_proof.1,
            &proof.utxo_inclusion_proof.0,
            &is_not_zero,
        )?;

        // 2. the shielded transaction tx exists in a transation tree T^{tx} with root r^{tx}
        plasma_blind_config.tx_tree.conditionally_check_index(
            &proof.block.tx_tree_root,
            &proof.utxo_tree_root,
            &proof.tx_inclusion_proof.1,
            &proof.tx_inclusion_proof.0,
            &is_not_zero,
        )?;

        // 3. the transaction tree T has been signed by the sender s
        plasma_blind_config.signer_tree.conditionally_check_index(
            &proof.block.signer_tree_root,
            &proof.signer,
            &proof.signer_inclusion_proof.1,
            &proof.signer_inclusion_proof.0,
            &is_not_zero,
        )?;

        // 4. block is contained within the block tree
        let block_hash =
            BlockVarCRH::evaluate(&plasma_blind_config.block_crh_config, &proof.block)?;

        plasma_blind_config.block_tree.conditionally_check_index(
            &proof.block_tree_root,
            &block_hash,
            &proof.block_inclusion_proof.1,
            &proof.block_inclusion_proof.0,
            &is_not_zero,
        )?;

        // 5. nullifier computation is correct
        NullifierVar::new(
            &plasma_blind_config.poseidon_config,
            sk,
            proof.utxo_inclusion_proof.1.clone(),
            proof.tx_inclusion_proof.1.clone(),
            proof.block.height.clone(),
        )?
        .value
        .conditional_enforce_equal(&nullifier.value, &is_not_zero)?;

        // 6. ensure that user is utxo's owner
        self.pk.conditional_enforce_equal(&pk, &is_not_zero)?;

        Ok(())
    }
}

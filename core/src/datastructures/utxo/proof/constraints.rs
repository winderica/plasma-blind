use crate::primitives::crh::constraints::BlockVarCRH;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, constraints::TwoToOneCRHGadget},
    merkle_tree::{
        Config,
        constraints::{ConfigGadget, PathVar},
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::gr1cs::SynthesisError;

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
    primitives::sparsemt::{
        SparseConfig,
        constraints::{MerkleSparseTreePathVar, SparseConfigGadget},
    },
};

use super::UTXOProof;

pub struct UTXOProofVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    TC: Config, // transaction tree config
    TCG: SparseConfigGadget<TC, C::BaseField, Leaf: Sized>,
    SC: Config, // signer tree config
    SCG: SparseConfigGadget<SC, C::BaseField>,
> {
    block: BlockVar<C, TC, TCG, SC, SCG>,
    tx: <TCG as ConfigGadget<TC, C::BaseField>>::Leaf,
    utxo: UTXOVar<C, CVar>,
    utxo_index: FpVar<C::BaseField>,
    utxo_inclusion_proof: PathVar<
        ShieldedTransactionConfig<C>,
        C::BaseField,
        ShieldedTransactionConfigGadget<C, CVar>,
    >,
    signer_inclusion_proof: MerkleSparseTreePathVar<SC, C::BaseField, SCG>,
    tx_inclusion_proof: MerkleSparseTreePathVar<TC, C::BaseField, TCG>,
    tx_index: FpVar<C::BaseField>,
    block_tree_root: <BlockTreeConfigGadget<C, CVar> as ConfigGadget<
        BlockTreeConfig<C>,
        C::BaseField,
    >>::InnerDigest,
    block_inclusion_proof:
        MerkleSparseTreePathVar<BlockTreeConfig<C>, C::BaseField, BlockTreeConfigGadget<C, CVar>>,
    nullifier: NullifierVar<C::BaseField>,
}

impl<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    TC: SparseConfig<InnerDigest = C::BaseField> + Clone, // transaction tree config
    TCG: SparseConfigGadget<
            TC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            Leaf = ShieldedTransactionVar<C, CVar>,
        >,
    SC: SparseConfig<InnerDigest = C::BaseField> + Clone, // signer tree config
    SCG: SparseConfigGadget<SC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
> AllocVar<UTXOProof<C, TC, SC>, C::BaseField> for UTXOProofVar<C, CVar, TC, TCG, SC, SCG>
{
    fn new_variable<T: std::borrow::Borrow<UTXOProof<C, TC, SC>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let res = f()?;
        let utxo_proof = res.borrow();

        let block = BlockVar::new_variable(cs.clone(), || Ok(utxo_proof.block.clone()), mode)?;
        let tx = <TCG as ConfigGadget<TC, C::BaseField>>::Leaf::new_variable(
            cs.clone(),
            || Ok(utxo_proof.tx.clone()),
            mode,
        )?;
        let utxo = UTXOVar::new_variable(cs.clone(), || Ok(utxo_proof.utxo.clone()), mode)?;
        let utxo_index =
            FpVar::new_variable(cs.clone(), || Ok(utxo_proof.utxo_index.clone()), mode)?;
        let utxo_inclusion_proof = PathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.utxo_inclusion_proof.clone()),
            mode,
        )?;
        let signer_inclusion_proof = MerkleSparseTreePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.signer_inclusion_proof.clone()),
            mode,
        )?;
        let tx_inclusion_proof = MerkleSparseTreePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.tx_inclusion_proof.clone()),
            mode,
        )?;
        let tx_index = FpVar::new_variable(cs.clone(), || Ok(utxo_proof.tx_index), mode)?;

        let block_inclusion_proof = MerkleSparseTreePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.block_inclusion_proof.clone()),
            mode,
        )?;

        // note that nullifier and block tree root are public by default
        let block_tree_root = <BlockTreeConfigGadget<C, CVar> as ConfigGadget<
            BlockTreeConfig<C>,
            C::BaseField,
        >>::InnerDigest::new_input(cs.clone(), || {
            Ok(utxo_proof.block_tree_root)
        })?;
        let nullifier = NullifierVar::new_input(cs.clone(), || Ok(utxo_proof.nullifier.clone()))?;

        Ok(UTXOProofVar {
            block,
            tx,
            utxo,
            utxo_index,
            utxo_inclusion_proof,
            signer_inclusion_proof,
            tx_inclusion_proof,
            tx_index,
            block_tree_root,
            block_inclusion_proof,
            nullifier,
        })
    }
}

impl<
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
> UTXOProofVar<C, CVar, TC, TCG, SC, SCG>
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
        pk: PublicKeyVar<C, CVar>,
        plasma_blind_config: &PlasmaBlindConfigVar<C, CVar, TC, TCG, SC, SCG>,
    ) -> Result<(), SynthesisError> {
        // checks only apply when the utxo is not zero
        let is_not_zero = !self.utxo.amount.is_zero()?;

        // 1. utxo exists in a shielded transaction tx
        let is_in_tx = self.utxo_inclusion_proof.verify_membership(
            &plasma_blind_config.shielded_tx_leaf_config,
            &plasma_blind_config.shielded_tx_two_to_one_config,
            &self.tx.shielded_tx,
            &self.utxo,
        )?;
        is_in_tx.conditional_enforce_equal(&Boolean::Constant(true), &is_not_zero)?;

        // 2. the shielded transaction tx exists in a transation tree T^{tx} with root r^{tx}
        self.tx_inclusion_proof
            .conditionally_check_membership_with_index(
                &plasma_blind_config.tx_tree_leaf_config,
                &plasma_blind_config.tx_tree_two_to_one_config,
                &self.block.tx_tree_root,
                &self.tx,
                &self.tx_index,
                &is_not_zero,
            )?;

        // 3. the transaction tree T has been signed by the sender s
        self.signer_inclusion_proof.conditionally_check_membership(
            &plasma_blind_config.signer_tree_leaf_config,
            &plasma_blind_config.signer_tree_two_to_one_config,
            &self.block.signer_tree_root,
            &self.tx.from,
            &is_not_zero,
        )?;

        // 4. block is contained within the block tree
        let block_hash = BlockVarCRH::evaluate(&plasma_blind_config.block_crh_config, &self.block)?;

        self.block_inclusion_proof.conditionally_check_membership(
            &plasma_blind_config.block_tree_leaf_config,
            &plasma_blind_config.block_tree_two_to_one_config,
            &self.block_tree_root,
            &block_hash,
            &is_not_zero,
        )?;

        // 5. nullifier computation is correct
        let nullifier = NullifierVar::new(
            &plasma_blind_config.poseidon_config,
            sk,
            self.utxo_index.clone(),
            self.tx_index.clone(),
            self.block.height.clone(),
        )?;

        nullifier
            .value
            .conditional_enforce_equal(&self.nullifier.value, &is_not_zero)?;

        // 6. ensure that user is utxo's owner
        self.utxo.pk.conditional_enforce_equal(&pk, &is_not_zero)?;

        Ok(())
    }
}

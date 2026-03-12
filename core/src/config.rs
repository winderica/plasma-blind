use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::CRHParametersVar,
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use sonobe_primitives::transcripts::{
    Absorbable,
    griffin::{GriffinParams, constraints::crh::GriffinParamsVar},
};

use crate::{
    datastructures::shieldedtx::constraints::UTXOTreeGadget,
    primitives::{crh::utils::Init, sparsemt::constraints::MerkleSparseTreeGadget},
};

#[derive(Clone)]
pub struct PlasmaBlindConfig<Cfg: Init> {
    pub hash_config: Cfg,
    pub utxo_crh_config: Cfg,               // crh config for shielded_tx
    pub shielded_tx_leaf_config: (),        // crh config for shielded_tx
    pub shielded_tx_two_to_one_config: Cfg, // 2-to-1 crh config for shielded_tx
    pub tx_tree_leaf_config: (),            // crh config for tx tree
    pub tx_tree_n_to_one_config: Cfg,       // 2-to-1 config for tx tree
    pub signer_tree_leaf_config: (),        // crh config for signer tree
    pub signer_tree_n_to_one_config: Cfg,   // 2-to-1 config for signer tree
    pub nullifier_tree_leaf_config: Cfg,
    pub nullifier_tree_two_to_one_config: Cfg,
    pub block_tree_leaf_config: Cfg,     // crh config for block tree
    pub block_tree_n_to_one_config: Cfg, // 2-to-1 config for block tree
}

impl<Cfg: Init> PlasmaBlindConfig<Cfg> {
    pub fn new(
        hash_config: Cfg,
        utxo_crh_config: Cfg,               // crh config for shielded_tx
        shielded_tx_leaf_config: (),        // crh config for shielded_tx
        shielded_tx_two_to_one_config: Cfg, // 2-to-1 crh config for shielded_tx
        tx_tree_leaf_config: (),            // crh config for tx tree
        tx_tree_n_to_one_config: Cfg,       // 2-to-1 config for tx tree
        signer_tree_leaf_config: (),        // crh config for signer tree
        signer_tree_n_to_one_config: Cfg,   // 2-to-1 config for signer tree
        nullifier_tree_leaf_config: Cfg,
        nullifier_tree_two_to_one_config: Cfg,
        block_tree_leaf_config: Cfg,     // crh config for block tree
        block_tree_n_to_one_config: Cfg, // 2-to-1 config for block tree
    ) -> Self {
        Self {
            hash_config,
            utxo_crh_config,
            shielded_tx_leaf_config,
            shielded_tx_two_to_one_config,
            tx_tree_leaf_config,
            tx_tree_n_to_one_config,
            signer_tree_leaf_config,
            signer_tree_n_to_one_config,
            nullifier_tree_leaf_config,
            nullifier_tree_two_to_one_config,
            block_tree_leaf_config,
            block_tree_n_to_one_config,
        }
    }
}

pub struct PlasmaBlindConfigVar<Cfg: Init> {
    pub hash_config: Cfg::Var,
    pub utxo_crh_config: Cfg::Var, // crh config for block hash
    pub tx_tree_n_to_one_config: Cfg::Var,
    pub signer_tree_n_to_one_config: Cfg::Var,
    pub block_tree_leaf_config: Cfg::Var,
    pub block_tree_n_to_one_config: Cfg::Var,
    pub utxo_tree: UTXOTreeGadget<Cfg>,
}

impl<Cfg: Init> AllocVar<PlasmaBlindConfig<Cfg>, Cfg::F> for PlasmaBlindConfigVar<Cfg> {
    fn new_variable<T: std::borrow::Borrow<PlasmaBlindConfig<Cfg>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<Cfg::F>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        _mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let t = f()?;
        let config = t.borrow();
        let hash_config = Cfg::Var::new_constant(cs.clone(), &config.hash_config)?;

        let utxo_crh_config = AllocVar::new_constant(cs.clone(), &config.utxo_crh_config)?;
        let block_tree_leaf_config =
            AllocVar::new_constant(cs.clone(), &config.block_tree_leaf_config)?;

        let block_tree_n_to_one_config =
            AllocVar::new_constant(cs.clone(), &config.block_tree_n_to_one_config)?;

        let utxo_tree = MerkleSparseTreeGadget::new(
            AllocVar::new_constant(cs.clone(), config.shielded_tx_leaf_config)?,
            AllocVar::new_constant(cs.clone(), &config.shielded_tx_two_to_one_config)?,
        );

        let tx_tree_n_to_one_config =
            AllocVar::new_constant(cs.clone(), &config.tx_tree_n_to_one_config)?;
        let signer_tree_n_to_one_config =
            AllocVar::new_constant(cs.clone(), &config.signer_tree_n_to_one_config)?;

        Ok(Self {
            hash_config,
            utxo_crh_config,
            block_tree_leaf_config,
            block_tree_n_to_one_config,
            utxo_tree,
            tx_tree_n_to_one_config,
            signer_tree_n_to_one_config,
        })
    }
}

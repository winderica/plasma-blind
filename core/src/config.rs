use ark_crypto_primitives::{
    crh::{
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
        poseidon::constraints::CRHParametersVar,
    },
    merkle_tree::{Config, constraints::ConfigGadget},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar};

use crate::{
    datastructures::{
        blocktree::{
            BlockTreeConfig,
            constraints::{BlockTreeConfigGadget, BlockTreeGadget},
        },
        shieldedtx::{
            ShieldedTransactionConfig,
            constraints::{ShieldedTransactionConfigGadget, UTXOTreeGadget},
        },
        signerlist::{
            SignerTreeConfig,
            constraints::{SignerTreeConfigGadget, SignerTreeGadget},
        },
        txtree::{
            TransactionTreeConfig,
            constraints::{TransactionTreeConfigGadget, TransactionTreeGadget},
        },
    },
    primitives::{
        sparsemt::{
            SparseConfig,
            constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
        },
    },
};

#[derive(Clone)]
pub struct PlasmaBlindConfig<F: PrimeField> {
    pub poseidon_config: PoseidonConfig<F>, // poseidon config, used for both h(utxo) and h(sk)
    pub utxo_crh_config: PoseidonConfig<F>, // crh config for shielded_tx
    pub shielded_tx_leaf_config: (),        // crh config for shielded_tx
    pub shielded_tx_two_to_one_config: PoseidonConfig<F>, // 2-to-1 crh config for shielded_tx
    pub tx_tree_leaf_config: (),            // crh config for tx tree
    pub tx_tree_two_to_one_config: PoseidonConfig<F>, // 2-to-1 config for tx tree
    pub signer_tree_leaf_config: (),        // crh config for signer tree
    pub signer_tree_two_to_one_config: PoseidonConfig<F>, // 2-to-1 config for signer tree
    pub nullifier_tree_leaf_config: PoseidonConfig<F>,
    pub nullifier_tree_two_to_one_config: PoseidonConfig<F>,
    pub block_tree_leaf_config: PoseidonConfig<F>, // crh config for block tree
    pub block_tree_two_to_one_config: PoseidonConfig<F>, // 2-to-1 config for block tree
}

impl<F: PrimeField> PlasmaBlindConfig<F> {
    pub fn new(
        poseidon_config: PoseidonConfig<F>, // poseidon config, used for both h(utxo) and h(sk)
        utxo_crh_config: PoseidonConfig<F>, // crh config for shielded_tx
        shielded_tx_leaf_config: (),        // crh config for shielded_tx
        shielded_tx_two_to_one_config: PoseidonConfig<F>, // 2-to-1 crh config for shielded_tx
        tx_tree_leaf_config: (),            // crh config for tx tree
        tx_tree_two_to_one_config: PoseidonConfig<F>, // 2-to-1 config for tx tree
        signer_tree_leaf_config: (),        // crh config for signer tree
        signer_tree_two_to_one_config: PoseidonConfig<F>, // 2-to-1 config for signer tree
        nullifier_tree_leaf_config: PoseidonConfig<F>,
        nullifier_tree_two_to_one_config: PoseidonConfig<F>,
        block_tree_leaf_config: PoseidonConfig<F>, // crh config for block tree
        block_tree_two_to_one_config: PoseidonConfig<F>, // 2-to-1 config for block tree
    ) -> Self {
        Self {
            poseidon_config,
            utxo_crh_config,
            shielded_tx_leaf_config,
            shielded_tx_two_to_one_config,
            tx_tree_leaf_config,
            tx_tree_two_to_one_config,
            signer_tree_leaf_config,
            signer_tree_two_to_one_config,
            nullifier_tree_leaf_config,
            nullifier_tree_two_to_one_config,
            block_tree_leaf_config,
            block_tree_two_to_one_config,
        }
    }
}

pub struct PlasmaBlindConfigVar<F: PrimeField + Absorb> {
    pub poseidon_config: CRHParametersVar<F>, // poseidon config, used for both h(utxo) and h(sk)
    pub utxo_crh_config: CRHParametersVar<F>, // crh config for block hash
    pub utxo_tree: UTXOTreeGadget<F>,
    pub tx_tree: TransactionTreeGadget<F>,
    pub signer_tree: SignerTreeGadget<F>,
    pub block_tree: BlockTreeGadget<F>,
}

impl<F: PrimeField + Absorb> AllocVar<PlasmaBlindConfig<F>, F> for PlasmaBlindConfigVar<F> {
    fn new_variable<T: std::borrow::Borrow<PlasmaBlindConfig<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let t = f()?;
        let config = t.borrow();
        let poseidon_config = CRHParametersVar::new_constant(cs.clone(), &config.poseidon_config)?;

        let utxo_crh_config = AllocVar::new_constant(cs.clone(), &config.utxo_crh_config)?;

        let utxo_tree = MerkleSparseTreeGadget::new(
            AllocVar::new_constant(cs.clone(), &config.shielded_tx_leaf_config)?,
            AllocVar::new_constant(cs.clone(), &config.shielded_tx_two_to_one_config)?,
        );

        let tx_tree = MerkleSparseTreeGadget::new(
            AllocVar::new_constant(cs.clone(), &())?,
            AllocVar::new_constant(cs.clone(), &config.tx_tree_two_to_one_config)?,
        );

        let signer_tree = MerkleSparseTreeGadget::new(
            AllocVar::new_constant(cs.clone(), &config.signer_tree_leaf_config)?,
            AllocVar::new_constant(cs.clone(), &config.signer_tree_two_to_one_config)?,
        );

        let block_tree = MerkleSparseTreeGadget::new(
            AllocVar::new_constant(cs.clone(), &config.block_tree_leaf_config)?,
            AllocVar::new_constant(cs.clone(), &config.block_tree_two_to_one_config)?,
        );

        Ok(Self {
            poseidon_config,
            utxo_crh_config,
            utxo_tree,
            tx_tree,
            signer_tree,
            block_tree,
        })
    }
}

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
        blocktree::{BlockTreeConfig, constraints::BlockTreeConfigGadget},
        shieldedtx::{ShieldedTransactionConfig, constraints::ShieldedTransactionConfigGadget},
        signerlist::{SignerTreeConfig, constraints::SignerTreeConfigGadget},
        txtree::{TransactionTreeConfig, constraints::TransactionTreeConfigGadget},
    },
    primitives::{
        crh::{BlockCRH, constraints::BlockVarCRH},
        sparsemt::{
            SparseConfig,
            constraints::{MerkleSparseTreeGadget, SparseConfigGadget},
        },
    },
};

#[derive(Clone)]
pub struct PlasmaBlindConfig<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    pub poseidon_config: PoseidonConfig<C::BaseField>, // poseidon config, used for both h(utxo) and h(sk)
    pub utxo_crh_config: PoseidonConfig<C::BaseField>, // crh config for shielded_tx
    pub shielded_tx_leaf_config: (),                   // crh config for shielded_tx
    pub shielded_tx_two_to_one_config: PoseidonConfig<C::BaseField>, // 2-to-1 crh config for shielded_tx
    pub tx_tree_leaf_config: (),                                     // crh config for tx tree
    pub tx_tree_two_to_one_config: PoseidonConfig<C::BaseField>,     // 2-to-1 config for tx tree
    pub signer_tree_leaf_config: PoseidonConfig<C::BaseField>,       // crh config for signer tree
    pub signer_tree_two_to_one_config: PoseidonConfig<C::BaseField>, // 2-to-1 config for signer tree
    pub block_crh_config: PoseidonConfig<C::BaseField>,              // crh config for block hash
    pub block_tree_leaf_config: (),                                  // crh config for block tree
    pub block_tree_two_to_one_config: PoseidonConfig<C::BaseField>,  // 2-to-1 config for block tree
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> PlasmaBlindConfig<C> {
    pub fn new(
        poseidon_config: PoseidonConfig<C::BaseField>, // poseidon config, used for both h(utxo) and h(sk)
        utxo_crh_config: PoseidonConfig<C::BaseField>, // crh config for shielded_tx
        shielded_tx_leaf_config: (),                   // crh config for shielded_tx
        shielded_tx_two_to_one_config: PoseidonConfig<C::BaseField>, // 2-to-1 crh config for shielded_tx
        tx_tree_leaf_config: (),                                     // crh config for tx tree
        tx_tree_two_to_one_config: PoseidonConfig<C::BaseField>,     // 2-to-1 config for tx tree
        signer_tree_leaf_config: PoseidonConfig<C::BaseField>,       // crh config for signer tree
        signer_tree_two_to_one_config: PoseidonConfig<C::BaseField>, // 2-to-1 config for signer tree
        block_crh_config: PoseidonConfig<C::BaseField>,              // crh config for block hash
        block_tree_leaf_config: (),                                  // crh config for block tree
        block_tree_two_to_one_config: PoseidonConfig<C::BaseField>,  // 2-to-1 config for block tree
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
            block_crh_config,
            block_tree_leaf_config,
            block_tree_two_to_one_config,
        }
    }
}

pub struct PlasmaBlindConfigVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    pub poseidon_config: CRHParametersVar<C::BaseField>, // poseidon config, used for both h(utxo) and h(sk)
    pub utxo_crh_config: CRHParametersVar<C::BaseField>, // crh config for block hash
    pub utxo_tree: MerkleSparseTreeGadget<
        ShieldedTransactionConfig<C::BaseField>,
        C::BaseField,
        ShieldedTransactionConfigGadget<C::BaseField>,
    >,
    pub tx_tree: MerkleSparseTreeGadget<
        TransactionTreeConfig<C::BaseField>,
        C::BaseField,
        TransactionTreeConfigGadget<C::BaseField>,
    >,
    pub signer_tree:
        MerkleSparseTreeGadget<SignerTreeConfig<C>, C::BaseField, SignerTreeConfigGadget<C, CVar>>,
    pub block_crh_config: CRHParametersVar<C::BaseField>, // crh config for block hash
    pub block_tree: MerkleSparseTreeGadget<
        BlockTreeConfig<C::BaseField>,
        C::BaseField,
        BlockTreeConfigGadget<C::BaseField>,
    >,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<PlasmaBlindConfig<C>, C::BaseField> for PlasmaBlindConfigVar<C, CVar>
{
    fn new_variable<T: std::borrow::Borrow<PlasmaBlindConfig<C>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::BaseField>>,
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

        let block_crh_config =
            AllocVar::new_variable(cs.clone(), || Ok(config.block_crh_config.clone()), mode)?;
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
            block_crh_config,
            block_tree,
        })
    }
}

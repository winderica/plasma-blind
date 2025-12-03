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
    },
    primitives::{
        crh::{BlockCRH, constraints::BlockVarCRH},
        sparsemt::{SparseConfig, constraints::SparseConfigGadget},
    },
};

#[derive(Clone)]
pub struct PlasmaBlindConfig<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: SparseConfig, // transaction tree config
    SC: SparseConfig, // signer tree config
> {
    pub poseidon_config: PoseidonConfig<C::BaseField>, // poseidon config, used for both h(utxo) and h(sk)
    pub shielded_tx_leaf_config:
        <<ShieldedTransactionConfig<C> as Config>::LeafHash as CRHScheme>::Parameters, // crh config for shielded_tx
    pub shielded_tx_two_to_one_config:
        <<ShieldedTransactionConfig<C> as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 crh config for shielded_tx
    pub tx_tree_leaf_config: <<TC as Config>::LeafHash as CRHScheme>::Parameters, // crh config for tx tree
    pub tx_tree_two_to_one_config: <<TC as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 config for tx tree
    pub signer_tree_leaf_config: <<SC as Config>::LeafHash as CRHScheme>::Parameters, // crh config for signer tree
    pub signer_tree_two_to_one_config:
        <<SC as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 config for signer tree
    pub block_crh_config: <BlockCRH<C::BaseField> as CRHScheme>::Parameters, // crh config for block hash
    pub block_tree_leaf_config: <<BlockTreeConfig<C> as Config>::LeafHash as CRHScheme>::Parameters, // crh config for block tree
    pub block_tree_two_to_one_config:
        <<BlockTreeConfig<C> as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 config for block tree
}

impl<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: SparseConfig, // transaction tree config
    SC: SparseConfig, // signer tree config
> PlasmaBlindConfig<C, TC, SC>
{
    pub fn new(
        poseidon_config: PoseidonConfig<C::BaseField>, // poseidon config, used for both h(utxo) and h(sk)
        shielded_tx_leaf_config:
        <<ShieldedTransactionConfig<C> as Config>::LeafHash as CRHScheme>::Parameters, // crh config for shielded_tx
        shielded_tx_two_to_one_config:
        <<ShieldedTransactionConfig<C> as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 crh config for shielded_tx
        tx_tree_leaf_config: <<TC as Config>::LeafHash as CRHScheme>::Parameters, // crh config for tx tree
        tx_tree_two_to_one_config: <<TC as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 config for tx tree
        signer_tree_leaf_config: <<SC as Config>::LeafHash as CRHScheme>::Parameters, // crh config for signer tree
        signer_tree_two_to_one_config:
        <<SC as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 config for signer tree
        block_crh_config: <BlockCRH<C::BaseField> as CRHScheme>::Parameters, // crh config for block hash
        block_tree_leaf_config: <<BlockTreeConfig<C> as Config>::LeafHash as CRHScheme>::Parameters, // crh config for block tree
        block_tree_two_to_one_config:
        <<BlockTreeConfig<C> as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters, // 2-to-1 config for block tree
    ) -> Self {
        Self {
            poseidon_config,
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
    TC: SparseConfig, // transaction tree config
    TCG: SparseConfigGadget<TC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
    SC: SparseConfig, // signer tree config
    SCG: SparseConfigGadget<SC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
> {
    pub poseidon_config: CRHParametersVar<C::BaseField>, // poseidon config, used for both h(utxo) and h(sk)
    pub shielded_tx_leaf_config: <<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::LeafHash as CRHSchemeGadget<
        <ShieldedTransactionConfig<C> as Config>::LeafHash,
        C::BaseField,
    >>::ParametersVar, // crh config for shielded_tx
    pub shielded_tx_two_to_one_config: <<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <ShieldedTransactionConfig<C> as Config>::TwoToOneHash,
        C::BaseField,
    >>::ParametersVar, // 2-to-1 crh config for shielded_tx
    pub tx_tree_leaf_config:
        <<TCG as ConfigGadget<TC, C::BaseField>>::LeafHash as CRHSchemeGadget<
            <TC as Config>::LeafHash,
            C::BaseField,
        >>::ParametersVar, // crh config for tx tree
    pub tx_tree_two_to_one_config:
        <<TCG as ConfigGadget<TC, C::BaseField>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
            <TC as Config>::TwoToOneHash,
            C::BaseField,
        >>::ParametersVar, // 2-to-1 config for tx tree
    pub signer_tree_leaf_config:
        <<SCG as ConfigGadget<SC, C::BaseField>>::LeafHash as CRHSchemeGadget<
            <SC as Config>::LeafHash,
            C::BaseField,
        >>::ParametersVar, // crh config for signer tree
    pub signer_tree_two_to_one_config:
        <<SCG as ConfigGadget<SC, C::BaseField>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
            <SC as Config>::TwoToOneHash,
            C::BaseField,
        >>::ParametersVar, // 2-to-1 config for signer tree
    pub block_crh_config: <BlockVarCRH<C, TC, TCG, SC, SCG> as CRHSchemeGadget<
        BlockCRH<C::BaseField>,
        C::BaseField,
    >>::ParametersVar, // crh config for block hash
    pub block_tree_leaf_config: <<BlockTreeConfigGadget<C, CVar> as ConfigGadget<
        BlockTreeConfig<C>,
        C::BaseField,
    >>::LeafHash as CRHSchemeGadget<
        <BlockTreeConfig<C> as Config>::LeafHash,
        C::BaseField,
    >>::ParametersVar, // crh config for block tree
    pub block_tree_two_to_one_config: <<BlockTreeConfigGadget<C, CVar> as ConfigGadget<
        BlockTreeConfig<C>,
        C::BaseField,
    >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <BlockTreeConfig<C> as Config>::TwoToOneHash,
        C::BaseField,
    >>::ParametersVar, // 2-to-1 config for block tree
}

impl<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    TC: SparseConfig, // transaction tree config
    TCG: SparseConfigGadget<TC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
    SC: SparseConfig, // signer tree config
    SCG: SparseConfigGadget<SC, C::BaseField, InnerDigest = FpVar<C::BaseField>>,
> AllocVar<PlasmaBlindConfig<C, TC, SC>, C::BaseField>
    for PlasmaBlindConfigVar<C, CVar, TC, TCG, SC, SCG>
{
    fn new_variable<T: std::borrow::Borrow<PlasmaBlindConfig<C, TC, SC>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let cs = cs.into().cs();
        let t = f()?;
        let config = t.borrow();
        let poseidon_config = CRHParametersVar::new_variable(
            cs.clone(),
            || Ok(config.poseidon_config.clone()),
            mode,
        )?;

        let shielded_tx_leaf_config = <<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
            ShieldedTransactionConfig<C>,
            C::BaseField,
        >>::LeafHash as CRHSchemeGadget<
            <ShieldedTransactionConfig<C> as Config>::LeafHash,
            C::BaseField,
        >>::ParametersVar::new_variable(
            cs.clone(),
            || Ok(config.shielded_tx_leaf_config.clone()),
            mode,
        )?;
        let shielded_tx_two_to_one_config =
            <<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
                ShieldedTransactionConfig<C>,
                C::BaseField,
            >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <ShieldedTransactionConfig<C> as Config>::TwoToOneHash,
                C::BaseField,
            >>::ParametersVar::new_variable(
                cs.clone(),
                || Ok(config.shielded_tx_two_to_one_config.clone()),
                mode,
            )?;
        let tx_tree_leaf_config =
            <<TCG as ConfigGadget<TC, C::BaseField>>::LeafHash as CRHSchemeGadget<
                <TC as Config>::LeafHash,
                C::BaseField,
            >>::ParametersVar::new_variable(
                cs.clone(),
                || Ok(config.tx_tree_leaf_config.clone()),
                mode,
            )?; // crh config for tx tree
        let tx_tree_two_to_one_config =
            <<TCG as ConfigGadget<TC, C::BaseField>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <TC as Config>::TwoToOneHash,
                C::BaseField,
            >>::ParametersVar::new_variable(
                cs.clone(),
                || Ok(config.tx_tree_two_to_one_config.clone()),
                mode,
            )?; // 2-to-1 config for tx tree
        let signer_tree_leaf_config =
            <<SCG as ConfigGadget<SC, C::BaseField>>::LeafHash as CRHSchemeGadget<
                <SC as Config>::LeafHash,
                C::BaseField,
            >>::ParametersVar::new_variable(
                cs.clone(),
                || Ok(config.signer_tree_leaf_config.clone()),
                mode,
            )?;
        let signer_tree_two_to_one_config =
            <<SCG as ConfigGadget<SC, C::BaseField>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <SC as Config>::TwoToOneHash,
                C::BaseField,
            >>::ParametersVar::new_variable(
                cs.clone(),
                || Ok(config.signer_tree_two_to_one_config.clone()),
                mode,
            )?;
        let block_crh_config = <BlockVarCRH<C, TC, TCG, SC, SCG> as CRHSchemeGadget<
            BlockCRH<C::BaseField>,
            C::BaseField,
        >>::ParametersVar::new_variable(
            cs.clone(), || Ok(config.block_crh_config.clone()), mode
        )?;
        let block_tree_leaf_config = <<BlockTreeConfigGadget<C, CVar> as ConfigGadget<
            BlockTreeConfig<C>,
            C::BaseField,
        >>::LeafHash as CRHSchemeGadget<
            <BlockTreeConfig<C> as Config>::LeafHash,
            C::BaseField,
        >>::ParametersVar::new_variable(
            cs.clone(), || Ok(config.block_tree_leaf_config), mode
        )?;
        let block_tree_two_to_one_config = <<BlockTreeConfigGadget<C, CVar> as ConfigGadget<
            BlockTreeConfig<C>,
            C::BaseField,
        >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
            <BlockTreeConfig<C> as Config>::TwoToOneHash,
            C::BaseField,
        >>::ParametersVar::new_variable(
            cs.clone(),
            || Ok(config.block_tree_two_to_one_config.clone()),
            mode,
        )?;

        Ok(Self {
            poseidon_config,
            shielded_tx_leaf_config,
            shielded_tx_two_to_one_config,
            tx_tree_leaf_config,
            tx_tree_two_to_one_config,
            signer_tree_leaf_config,
            signer_tree_two_to_one_config,
            block_crh_config,
            block_tree_leaf_config,
            block_tree_two_to_one_config,
        })
    }
}

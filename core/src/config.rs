use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget, poseidon::constraints::CRHParametersVar},
    merkle_tree::{Config, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

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

pub struct PlasmaBlindConfig<
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
    pub block_hash_config: <BlockVarCRH<C, TC, TCG, SC, SCG> as CRHSchemeGadget<
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

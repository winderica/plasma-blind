pub mod datastructures;
pub mod primitives;

use crate::datastructures::transparenttx::constraints::TransparentTransactionVar;
use ark_crypto_primitives::{
    Error,
    crh::{
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
        poseidon::{
            CRH, TwoToOneCRH,
            constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget},
        },
    },
    merkle_tree::{
        Config,
        constraints::{ConfigGadget, PathVar},
    },
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::{
    eq::EqGadget, fields::fp::FpVar, groups::CurveVar, prelude::Boolean, uint64::UInt64,
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::rand::Rng;
use datastructures::shieldedtx::{
    ShieldedTransaction, ShieldedTransactionConfig,
    constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
};

use crate::{
    datastructures::{
        keypair::constraints::PublicKeyVar,
        signerlist::{SignerTreeConfig, constraints::SignerTreeConfigGadget},
        utxo::{UTXO, constraints::UTXOVar},
    },
    primitives::{
        crh::{UTXOCRH, constraints::UTXOVarCRH},
        sparsemt::constraints::MerkleSparseTreePathVar,
    },
};

const TX_TREE_HEIGHT: u64 = 13;
const SIGNER_TREE_HEIGHT: u64 = TX_TREE_HEIGHT;

type UserId = usize;

#[derive(Clone, Debug)]
pub struct Nullifier<F> {
    value: F,
}

impl<F: PrimeField + Absorb> Nullifier<F> {
    pub fn new(
        cfg: &PoseidonConfig<F>,
        sk: F,
        i: usize,
        j: usize,
        t: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            value: CRH::evaluate(
                cfg,
                [sk, F::from(i as u64), F::from(j as u64), F::from(t as u64)],
            )?,
        })
    }
}

#[derive(Clone, Debug)]
struct NullifierVar<F: PrimeField> {
    value: FpVar<F>,
}

impl<F: PrimeField + Absorb> NullifierVar<F> {
    fn new(
        cfg: &CRHParametersVar<F>,
        sk: &FpVar<F>,
        i: &UInt64<F>,
        j: &UInt64<F>,
        t: &UInt64<F>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            value: CRHGadget::evaluate(cfg, &[sk.clone(), i.to_fp()?, j.to_fp()?, t.to_fp()?])?,
        })
    }
}

fn commit_utxo<C: CurveGroup<BaseField: PrimeField + Absorb>>(
    cfg: &PoseidonConfig<C::BaseField>,
    utxo: &UTXO<C>,
    mut rng: impl Rng,
) -> Result<(C::BaseField, C::BaseField), Error> {
    let r = C::BaseField::rand(&mut rng);
    let cm = TwoToOneCRH::evaluate(cfg, UTXOCRH::evaluate(cfg, utxo)?, r)?;

    Ok((cm, r))
}

fn commit_utxo_var<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
>(
    cfg: &CRHParametersVar<C::BaseField>,
    utxo: &UTXOVar<C, CVar>,
    r: &FpVar<C::BaseField>,
) -> Result<FpVar<C::BaseField>, SynthesisError> {
    TwoToOneCRHGadget::evaluate(cfg, &UTXOVarCRH::evaluate(cfg, utxo)?, r)
}

// NOTE: here is how I would think about it? (in this setup we don't need the shielded tx)
// - inputs of the plain tx sum up to outputs of the plain tx
// - the plain tx is correctly formatted into a committed tx
// - the committed tx is the root of a tree whose leaves are elements of the above plain tx
// - the committed tx inputs UTXOs are from leaves of some other committed txs
// - the committed tx inputs UTXOs "to" field correspond to my pubkey
// - the committed tx inputs UTXOs resolve to a list of nullifiers
// - those other committed txs are in previous tx trees (don't worry about proving that those tx
// trees are from actual, previously built blocks, this will be the task of the aggregator)
// - those other committed txs have been signed (don't worry about proving that those signer
// trees are from actual, previously built blocks, this will be the task of the aggregator)
fn tx_validity<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>(
    cfg: &CRHParametersVar<C::BaseField>,
    sk: &FpVar<C::BaseField>, // TODO: sk and pk no longer being EC
    plain_tx: &TransparentTransactionVar<C, CVar>,
    // leaf mt params of shielded tx
    shielded_tx_leaf_config: &<<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::LeafHash as CRHSchemeGadget<
        <ShieldedTransactionConfig<C> as Config>::LeafHash,
        C::BaseField,
    >>::ParametersVar,
    // two-to-one mt params of shielded tx
    shielded_tx_two_to_one_config: &<<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <ShieldedTransactionConfig<C> as Config>::TwoToOneHash,
        C::BaseField,
    >>::ParametersVar,
    shielded_tx: &ShieldedTransactionVar<C, CVar>,
    // input utxos (first half of tree)
    shielded_tx_inputs: &[<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::Leaf],
    // output utxos (second half of tree)
    shielded_tx_outputs: &[<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::Leaf],
    // proving the shielded tx is correctly built
    shielded_tx_proof: &[PathVar<
        ShieldedTransactionConfig<C>,
        C::BaseField,
        ShieldedTransactionConfigGadget<C, CVar>,
    >],
    // nullifiers for shielded tx inputs
    nullifiers: &[NullifierVar<C::BaseField>],
    utxo_tree_root: &FpVar<C::BaseField>,
    signer_tree_root: &FpVar<C::BaseField>,
    transaction_indexes: &[UInt64<C::BaseField>],
    utxo_indexes: &[UInt64<C::BaseField>],
    signer_indexes: &[UInt64<C::BaseField>],
    //utxo_paths: &[MerkleSparseTreePathVar<
    //    CommittedUTXOTreeConfig<C::BaseField>,
    //    C::BaseField,
    //    CommittedUTXOTreeConfigGadget<C::BaseField>,
    //>],
    signer_paths: &[MerkleSparseTreePathVar<
        SignerTreeConfig<C>,
        C::BaseField,
        SignerTreeConfigGadget<C, CVar>,
    >],
    sender_pks: &[PublicKeyVar<C, CVar>],

    block_tree_root: &FpVar<C::BaseField>,
    block_index: &UInt64<C::BaseField>,
) -> Result<(), SynthesisError> {
    // TODO: filter dummy UTXOs
    // TODO: add transaction indexes to nullifier computation
    for (((nullifier, utxo), tx_idx), utxo_idx) in nullifiers
        .iter()
        .zip(shielded_tx_inputs.iter())
        .zip(transaction_indexes)
        .zip(utxo_indexes)
    {
        NullifierVar::new(cfg, sk, tx_idx, utxo_idx, block_index)?
            .value
            .enforce_equal(&nullifier.value)?;
    }
    // TODO: check sk and pk match

    // checks that shielded tx tree is correctly built
    for (path, leaf) in shielded_tx_proof
        .iter()
        .zip(shielded_tx_inputs.iter().chain(shielded_tx_outputs))
    {
        let res = path.verify_membership(
            shielded_tx_leaf_config,
            shielded_tx_two_to_one_config,
            &shielded_tx.shielded_tx,
            leaf,
        )?;
        res.enforce_equal(&Boolean::constant(true))?;
    }

    // NOTE: I think this is not needed anymore?
    //for ((utxo, cm), r) in plain_tx
    //    .outputs
    //    .iter()
    //    .zip(&shielded_tx.outputs)
    //    .zip(output_openings)
    //{
    //    commit_utxo_var(cfg, utxo, r)?.enforce_equal(cm)?;
    //}

    // checks plain_tx inputs sum up to outputs
    plain_tx
        .inputs
        .iter()
        .map(|i| &i.amount)
        .sum::<FpVar<C::BaseField>>()
        .enforce_equal(
            &plain_tx
                .inputs
                .iter()
                .map(|i| &i.amount)
                .sum::<FpVar<C::BaseField>>(),
        )?;

    for (((((utxo, r), utxo_idx), signer_idx), signer_path), sender_pk) in plain_tx
        .inputs
        .iter()
        .zip(shielded_tx_inputs)
        .zip(utxo_indexes)
        .zip(signer_indexes)
        //        .zip(utxo_paths)
        .zip(signer_paths)
        .zip(sender_pks)
    {
        // let cm = commit_utxo_var(cfg, utxo, r)?;
        //utxo_path.check_membership_with_index(
        //    cfg,
        //    cfg,
        //    utxo_tree_root,
        //    &(cm, signer_idx.clone()),
        //    utxo_idx,
        //)?;

        signer_path.check_membership_with_index(
            cfg,
            cfg,
            signer_tree_root,
            &sender_pk,
            signer_idx,
        )?;
    }

    todo!();
    Ok(())
}

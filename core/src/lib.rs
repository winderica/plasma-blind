pub mod datastructures;
pub mod primitives;

use crate::datastructures::transparenttx::constraints::TransparentTransactionVar;
use ark_crypto_primitives::{
    Error,
    crh::{
        CRHScheme, CRHSchemeGadget, TwoToOneCRHSchemeGadget,
        poseidon::{
            CRH,
            constraints::{CRHGadget, CRHParametersVar},
        },
    },
    merkle_tree::{
        Config, Path,
        constraints::{ConfigGadget, PathVar},
    },
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, groups::CurveVar, prelude::Boolean,
    uint64::UInt64,
};
use ark_relations::gr1cs::SynthesisError;
use datastructures::{
    block::{Block, constraints::BlockVar},
    blocktree::{BlockTreeConfig, constraints::BlockTreeConfigGadget},
    shieldedtx::{
        ShieldedTransaction, ShieldedTransactionConfig,
        constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
    },
    signerlist::constraints::SignerTreeConfigGadget,
    txtree::{TransactionTreeConfig, constraints::TransactionTreeConfigGadget},
    utxo::constraints::UTXOVar,
};
use primitives::sparsemt::{MerkleSparseTreePath, constraints::MerkleSparseTreePathVar};

use crate::datastructures::{signerlist::SignerTreeConfig, utxo::UTXO};

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

impl<F: PrimeField> AllocVar<Nullifier<F>, F> for NullifierVar<F> {
    fn new_variable<T: std::borrow::Borrow<Nullifier<F>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let res = f()?;
        let nullifier = res.borrow();
        Ok(NullifierVar {
            value: FpVar::new_variable(cs, || Ok(nullifier.value), mode)?,
        })
    }
}

// each input utxo requires a proof, attesting to its validity and nullifier
// valid utxo = included in shielded tx, within a tx tree which was signed at a certain block
// included within the block tree
pub struct UTXOProof<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    block: Block<C::BaseField>,
    tx: ShieldedTransaction<C>,
    utxo: UTXO<C>,
    utxo_inclusion_proof: Path<ShieldedTransactionConfig<C>>,
    signer_tree_root: <SignerTreeConfig<C> as Config>::InnerDigest,
    signer_inclusion_proof: MerkleSparseTreePath<SignerTreeConfig<C>>,
    tx_tree_root: <TransactionTreeConfig<C> as Config>::InnerDigest,
    tx_inclusion_proof: MerkleSparseTreePath<TransactionTreeConfig<C>>,
    tx_index: C::BaseField,
    block_tree_root: <BlockTreeConfig<C> as Config>::InnerDigest,
    block_inclusion_proof: MerkleSparseTreePath<BlockTreeConfig<C>>,
    nullifier: Nullifier<C::BaseField>,
}

pub struct UTXOProofVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    block: BlockVar<C::BaseField>,
    tx: ShieldedTransactionVar<C, CVar>,
    utxo: UTXOVar<C, CVar>,
    utxo_inclusion_proof: PathVar<
        ShieldedTransactionConfig<C>,
        C::BaseField,
        ShieldedTransactionConfigGadget<C, CVar>,
    >,
    signer_tree_root: <SignerTreeConfigGadget<C, CVar> as ConfigGadget<
        SignerTreeConfig<C>,
        C::BaseField,
    >>::InnerDigest,
    signer_inclusion_proof:
        MerkleSparseTreePathVar<SignerTreeConfig<C>, C::BaseField, SignerTreeConfigGadget<C, CVar>>,
    tx_tree_root: <TransactionTreeConfigGadget<C, CVar> as ConfigGadget<
        TransactionTreeConfig<C>,
        C::BaseField,
    >>::InnerDigest,
    tx_inclusion_proof: MerkleSparseTreePathVar<
        TransactionTreeConfig<C>,
        C::BaseField,
        TransactionTreeConfigGadget<C, CVar>,
    >,
    tx_index: FpVar<C::BaseField>,
    block_tree_root: <BlockTreeConfigGadget<C, CVar> as ConfigGadget<
        BlockTreeConfig<C>,
        C::BaseField,
    >>::InnerDigest,
    block_inclusion_proof:
        MerkleSparseTreePathVar<BlockTreeConfig<C>, C::BaseField, BlockTreeConfigGadget<C, CVar>>,
    nullifier: NullifierVar<C::BaseField>,
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
        let block = BlockVar::new_variable(cs.clone(), || Ok(utxo_proof.block.clone()), mode)?;
        let tx =
            ShieldedTransactionVar::new_variable(cs.clone(), || Ok(utxo_proof.tx.clone()), mode)?;
        let utxo = UTXOVar::new_variable(cs.clone(), || Ok(utxo_proof.utxo.clone()), mode)?;
        let utxo_inclusion_proof = PathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.utxo_inclusion_proof.clone()),
            mode,
        )?;
        let signer_tree_root = <SignerTreeConfigGadget<C, CVar> as ConfigGadget<
            SignerTreeConfig<C>,
            C::BaseField,
        >>::InnerDigest::new_variable(
            cs.clone(), || Ok(utxo_proof.signer_tree_root), mode
        )?;
        let signer_inclusion_proof = MerkleSparseTreePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.signer_inclusion_proof.clone()),
            mode,
        )?;
        let tx_tree_root = <TransactionTreeConfigGadget<C, CVar> as ConfigGadget<
            TransactionTreeConfig<C>,
            C::BaseField,
        >>::InnerDigest::new_variable(
            cs.clone(), || Ok(utxo_proof.tx_tree_root), mode
        )?;
        let tx_inclusion_proof = MerkleSparseTreePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.tx_inclusion_proof.clone()),
            mode,
        )?;
        let tx_index = FpVar::new_variable(cs.clone(), || Ok(utxo_proof.tx_index), mode)?;
        let block_tree_root = <BlockTreeConfigGadget<C, CVar> as ConfigGadget<
            BlockTreeConfig<C>,
            C::BaseField,
        >>::InnerDigest::new_variable(
            cs.clone(), || Ok(utxo_proof.block_tree_root), mode
        )?;
        let block_inclusion_proof = MerkleSparseTreePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.block_inclusion_proof.clone()),
            mode,
        )?;
        let nullifier =
            NullifierVar::new_variable(cs.clone(), || Ok(utxo_proof.nullifier.clone()), mode)?;

        Ok(UTXOProofVar {
            block,
            tx,
            utxo,
            utxo_inclusion_proof,
            signer_tree_root,
            signer_inclusion_proof,
            tx_tree_root,
            tx_inclusion_proof,
            tx_index,
            block_tree_root,
            block_inclusion_proof,
            nullifier,
        })
    }
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
    // proving the shielded tx is correctly built (all leaves are correct)
    shielded_tx_proof: &[PathVar<
        ShieldedTransactionConfig<C>,
        C::BaseField,
        ShieldedTransactionConfigGadget<C, CVar>,
    >],
) -> Result<(), SynthesisError> {
    // TODO: filter dummy UTXOs

    // compute utxo indexes from their merkle paths
    // let claimed_f = Boolean::le_bits_to_fp(&bits)?;

    // TODO: add transaction indexes to nullifier computation
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

    todo!();
    Ok(())
}

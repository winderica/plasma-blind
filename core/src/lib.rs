pub mod datastructures;
pub mod primitives;

use crate::datastructures::transparenttx::constraints::TransparentTransactionVar;
use ark_crypto_primitives::{
    Error,
    crh::{
        CRHScheme, CRHSchemeGadget, TwoToOneCRHSchemeGadget,
        poseidon::{
            CRH, TwoToOneCRH,
            constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget},
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
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
    prelude::Boolean,
    uint64::UInt64,
};
use ark_relations::gr1cs::SynthesisError;
use datastructures::{
    block::{Block, constraints::BlockVar},
    blocktree::{BlockTreeConfig, constraints::BlockTreeConfigGadget},
    keypair::constraints::PublicKeyVar,
    shieldedtx::{
        ShieldedTransaction, ShieldedTransactionConfig,
        constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
    },
    signerlist::constraints::SignerTreeConfigGadget,
    txtree::{TransactionTreeConfig, constraints::TransactionTreeConfigGadget},
    utxo::constraints::UTXOVar,
};
use primitives::sparsemt::{
    MerkleSparseTreePath, SparseConfig,
    constraints::{MerkleSparseTreePathVar, SparseConfigGadget},
};

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
pub struct UTXOProof<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: SparseConfig,
    SC: SparseConfig,
> {
    block: Block<C::BaseField>,
    tx: ShieldedTransaction<C>,
    utxo: UTXO<C>,
    utxo_inclusion_proof: Path<ShieldedTransactionConfig<C>>,
    signer_inclusion_proof: MerkleSparseTreePath<SC>,
    tx_inclusion_proof: MerkleSparseTreePath<TC>,
    tx_index: C::BaseField,
    block_tree_root: <BlockTreeConfig<C> as Config>::InnerDigest,
    block_inclusion_proof: MerkleSparseTreePath<BlockTreeConfig<C>>,
    nullifier: Nullifier<C::BaseField>,
}

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
        // block tree root is public
        let block_tree_root = <BlockTreeConfigGadget<C, CVar> as ConfigGadget<
            BlockTreeConfig<C>,
            C::BaseField,
        >>::InnerDigest::new_variable(
            cs.clone(),
            || Ok(utxo_proof.block_tree_root),
            AllocationMode::Input,
        )?;
        let block_inclusion_proof = MerkleSparseTreePathVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.block_inclusion_proof.clone()),
            mode,
        )?;
        // nullifiers are public
        let nullifier = NullifierVar::new_variable(
            cs.clone(),
            || Ok(utxo_proof.nullifier.clone()),
            AllocationMode::Input,
        )?;

        Ok(UTXOProofVar {
            block,
            tx,
            utxo,
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
    // 6. nullifiers are correct
    pub fn is_valid(
        &self,
        shielded_tx_leaf_config: &<<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
            ShieldedTransactionConfig<C>,
            C::BaseField,
        >>::LeafHash as CRHSchemeGadget<
            <ShieldedTransactionConfig<C> as Config>::LeafHash,
            C::BaseField,
        >>::ParametersVar,
        shielded_tx_two_to_one_config: &<<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
            ShieldedTransactionConfig<C>,
            C::BaseField,
        >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
            <ShieldedTransactionConfig<C> as Config>::TwoToOneHash,
            C::BaseField,
        >>::ParametersVar,
        tx_tree_leaf_config: &<<TCG as ConfigGadget<
            TC,
            C::BaseField,
        >>::LeafHash as CRHSchemeGadget<
            <TC as Config>::LeafHash,
            C::BaseField,
        >>::ParametersVar,
        tx_tree_two_to_one_config: &<<TCG as ConfigGadget<
            TC,
            C::BaseField,
        >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
            <TC as Config>::TwoToOneHash,
            C::BaseField,
        >>::ParametersVar,
        signer_tree_leaf_config: &<<SCG as ConfigGadget<
            SC,
            C::BaseField,
        >>::LeafHash as CRHSchemeGadget<
            <SC as Config>::LeafHash,
            C::BaseField,
        >>::ParametersVar,
        signer_tree_two_to_one_config: &<<SCG as ConfigGadget<
            SC,
            C::BaseField,
        >>::TwoToOneHash as TwoToOneCRHSchemeGadget<
            <SC as Config>::TwoToOneHash,
            C::BaseField,
        >>::ParametersVar,
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        // 1. utxo exists in a shielded transaction tx
        let utxo_is_in_shielded_tx = self.utxo_inclusion_proof.verify_membership(
            &shielded_tx_leaf_config,
            &shielded_tx_two_to_one_config,
            &self.tx.shielded_tx,
            &self.utxo,
        )?;
        utxo_is_in_shielded_tx.enforce_equal(&Boolean::constant(true))?;

        // 2. the shielded transaction tx exists in a transation tree T^{tx} with root r^{tx}
        self.tx_inclusion_proof.check_membership_with_index(
            &tx_tree_leaf_config,
            &tx_tree_two_to_one_config,
            &self.block.tx_tree_root,
            &self.tx,
            &self.tx_index,
        )?;

        // 3. the transaction tree T has been signed by the sender s
        self.signer_inclusion_proof.check_membership(
            &signer_tree_leaf_config,
            &signer_tree_two_to_one_config,
            &self.block.signer_tree_root,
            &self.tx.from,
        )?;

        // 4. the transaction tree exists in a block B
        // h(tx_tree, signer_tree) == block_hash
        // self.block.tx_tree_root.
        todo!()
    }
}

// NOTE: here is how I would think about it? (in this setup we don't need the shielded tx)
// - inputs of the plain tx sum up to outputs of the plain tx (ok)
// - the transparent tx leaves end up in shielded tx
// - the committed tx inputs UTXOs are valid
fn tx_validity<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>(
    cfg: &CRHParametersVar<C::BaseField>,
    sk: &FpVar<C::BaseField>, // TODO: sk and pk no longer being EC
    transparent_tx: &TransparentTransactionVar<C, CVar>,
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
    // input utxos proofs
    //    input_utxos_proofs: &[UTXOProofVar<C, CVar>],
) -> Result<(), SynthesisError> {
    // checks transparent tx inputs sum up to outputs
    transparent_tx
        .inputs
        .iter()
        .map(|i| &i.amount)
        .sum::<FpVar<C::BaseField>>()
        .enforce_equal(
            &transparent_tx
                .inputs
                .iter()
                .map(|i| &i.amount)
                .sum::<FpVar<C::BaseField>>(),
        )?;

    // the transparent tx leaves end up in shielded tx
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

    //   for utxo_proof in input_utxos_proofs {}

    todo!();
    Ok(())
}

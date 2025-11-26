pub mod config;
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
    merkle_tree::{Config, constraints::ConfigGadget},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use config::{PlasmaBlindConfig, PlasmaBlindConfigVar};
use datastructures::{
    block::{Block, constraints::BlockVar},
    blocktree::{BlockTreeConfig, constraints::BlockTreeConfigGadget},
    keypair::constraints::PublicKeyVar,
    shieldedtx::{
        ShieldedTransaction, ShieldedTransactionConfig,
        constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
    },
    utxo::constraints::UTXOVar,
};
use primitives::{
    crh::{BlockCRH, constraints::BlockVarCRH},
    sparsemt::{
        MerkleSparseTreePath, SparseConfig,
        constraints::{MerkleSparseTreePathVar, SparseConfigGadget},
    },
};

use crate::datastructures::utxo::UTXO;

const TX_TREE_HEIGHT: u64 = 13;
const SIGNER_TREE_HEIGHT: u64 = TX_TREE_HEIGHT;

#[derive(Clone, Debug)]
pub struct Nullifier<F> {
    value: F,
}

impl<F: PrimeField + Absorb> Nullifier<F> {
    pub fn new(
        cfg: &PoseidonConfig<F>,
        sk: F,
        utxo_idx: usize,
        tx_idx: usize,
        block_height: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            value: CRH::evaluate(
                cfg,
                [
                    sk,
                    F::from(utxo_idx as u64),
                    F::from(tx_idx as u64),
                    F::from(block_height as u64),
                ],
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
        utxo_idx: FpVar<F>,
        tx_idx: FpVar<F>,
        block_height: FpVar<F>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            value: CRHGadget::evaluate(cfg, &[sk.clone(), utxo_idx, tx_idx, block_height])?,
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
    utxo_index: C::BaseField,
    utxo_inclusion_proof: MerkleSparseTreePath<ShieldedTransactionConfig<C>>,
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
    utxo_index: FpVar<C::BaseField>,
    utxo_inclusion_proof: MerkleSparseTreePathVar<
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
        let utxo_inclusion_proof = MerkleSparseTreePathVar::new_variable(
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
        // 1. utxo exists in a shielded transaction tx
        self.utxo_inclusion_proof.check_membership_with_index(
            &plasma_blind_config.shielded_tx_leaf_config,
            &plasma_blind_config.shielded_tx_two_to_one_config,
            &self.tx.shielded_tx,
            &self.utxo,
            &self.utxo_index,
        )?;

        // 2. the shielded transaction tx exists in a transation tree T^{tx} with root r^{tx}
        self.tx_inclusion_proof.check_membership_with_index(
            &plasma_blind_config.tx_tree_leaf_config,
            &plasma_blind_config.tx_tree_two_to_one_config,
            &self.block.tx_tree_root,
            &self.tx,
            &self.tx_index,
        )?;

        // 3. the transaction tree T has been signed by the sender s
        self.signer_inclusion_proof.check_membership(
            &plasma_blind_config.signer_tree_leaf_config,
            &plasma_blind_config.signer_tree_two_to_one_config,
            &self.block.signer_tree_root,
            &self.tx.from,
        )?;

        // 4. block is contained within the block tree
        let block_hash =
            BlockVarCRH::evaluate(&plasma_blind_config.block_hash_config, &self.block)?;
        self.block_inclusion_proof.check_membership(
            &plasma_blind_config.block_tree_leaf_config,
            &plasma_blind_config.block_tree_two_to_one_config,
            &self.block_tree_root,
            &block_hash,
        )?;

        // 5. nullifier computation is correct
        let nullifier = NullifierVar::new(
            &plasma_blind_config.poseidon_config,
            sk,
            self.utxo_index.clone(),
            self.tx_index.clone(),
            self.block.height.clone(),
        )?;
        nullifier.value.enforce_equal(&self.nullifier.value)?;

        // 6. ensure that user is utxo's owner
        self.utxo.pk.enforce_equal(&pk)?;

        Ok(())
    }
}

pub fn tx_validity_circuit<
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
>(
    cs: ConstraintSystemRef<C::BaseField>,
    null_sk: &FpVar<C::BaseField>, // user secret for nullifier computation
    null_pk: &FpVar<C::BaseField>, // hash of user's secret, which is registered on the L1
    pk: PublicKeyVar<C, CVar>,     // user public key
    transparent_tx: &TransparentTransactionVar<C, CVar>, // transparent transaction
    shielded_tx: &ShieldedTransactionVar<C, CVar>, // shielded transaction (root of tree built from
    // transparent tx)
    shielded_tx_outputs: &[<ShieldedTransactionConfigGadget<C, CVar> as ConfigGadget<
        ShieldedTransactionConfig<C>,
        C::BaseField,
    >>::Leaf], // utxo leaves of shielded_tx
    shielded_tx_outputs_proofs: &[MerkleSparseTreePathVar<
        ShieldedTransactionConfig<C>,
        C::BaseField,
        ShieldedTransactionConfigGadget<C, CVar>,
    >], // proofs that output utxo is leaf of current shielded transaction
    shielded_tx_inputs_proofs: &[MerkleSparseTreePathVar<
        ShieldedTransactionConfig<C>,
        C::BaseField,
        ShieldedTransactionConfigGadget<C, CVar>,
    >], // proofs that output utxo is leaf of current shielded transaction
    input_utxos_proofs: &[UTXOProofVar<C, CVar, TC, TCG, SC, SCG>], // proof of existence of input
    // utxos
    plasma_blind_config: &PlasmaBlindConfigVar<C, CVar, TC, TCG, SC, SCG>,
) -> Result<(), SynthesisError> {
    // enforce correct nullifier secret is being used
    let null_pk_computed =
        CRHGadget::evaluate(&plasma_blind_config.poseidon_config, &[null_sk.clone()])?;
    null_pk_computed.enforce_equal(&null_pk)?;

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

    let mut utxo_idx = FpVar::new_constant(cs.clone(), C::BaseField::from(0))?;
    let one = FpVar::new_constant(cs.clone(), C::BaseField::ONE)?;

    for (input_utxo_proof, shielded_tx_inclusion_proof) in
        input_utxos_proofs.iter().zip(shielded_tx_inputs_proofs)
    {
        // check that input utxo is in the shielded tx
        shielded_tx_inclusion_proof.check_membership_with_index(
            &plasma_blind_config.shielded_tx_leaf_config,
            &plasma_blind_config.shielded_tx_two_to_one_config,
            &shielded_tx.shielded_tx,
            &input_utxo_proof.utxo,
            &utxo_idx,
        )?;

        input_utxo_proof.is_valid(null_sk, pk.clone(), &plasma_blind_config)?;

        utxo_idx += one.clone();
    }

    // the transparent tx output leaves end up in shielded tx
    for (shielded_tx_inclusion_proof, output_utxo) in
        shielded_tx_outputs_proofs.iter().zip(shielded_tx_outputs)
    {
        shielded_tx_inclusion_proof.check_membership_with_index(
            &plasma_blind_config.shielded_tx_leaf_config,
            &plasma_blind_config.shielded_tx_two_to_one_config,
            &shielded_tx.shielded_tx,
            output_utxo,
            &utxo_idx,
        )?;

        utxo_idx += one.clone();
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {

    #[test]
    fn test_validity_circuit() {}
}

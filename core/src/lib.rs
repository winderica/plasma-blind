pub mod config;
use ark_r1cs_std::{fields::FieldVar, prelude::Boolean};
use ark_std::One;
pub mod datastructures;
pub mod primitives;

use crate::datastructures::transparenttx::constraints::TransparentTransactionVar;
use ark_crypto_primitives::{
    Error,
    crh::{
        CRHScheme, CRHSchemeGadget,
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
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, groups::CurveVar};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use config::PlasmaBlindConfigVar;
use datastructures::{
    TX_IO_SIZE,
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
    crh::constraints::BlockVarCRH,
    sparsemt::{
        MerkleSparseTreePath, SparseConfig,
        constraints::{MerkleSparseTreePathVar, SparseConfigGadget},
    },
};

use crate::datastructures::utxo::UTXO;

const TX_TREE_HEIGHT: u64 = 13;
const SIGNER_TREE_HEIGHT: u64 = TX_TREE_HEIGHT;

#[derive(Clone, Debug, Default)]
pub struct Nullifier<F> {
    value: F,
}

impl<F: PrimeField + Absorb> Nullifier<F> {
    pub fn new(
        cfg: &PoseidonConfig<F>,
        sk: F,
        utxo_idx: u8,
        tx_idx: usize,
        block_height: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            value: CRH::evaluate(
                cfg,
                [
                    sk,
                    F::from(utxo_idx),
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
#[derive(Default, Clone)]
pub struct UTXOProof<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: SparseConfig,
    SC: SparseConfig,
> {
    block: Block<C::BaseField>,
    tx: ShieldedTransaction<C>,
    tx_index: C::BaseField,
    utxo: UTXO<C>,
    utxo_index: C::BaseField,
    utxo_inclusion_proof: Path<ShieldedTransactionConfig<C>>,
    signer_inclusion_proof: MerkleSparseTreePath<SC>,
    tx_inclusion_proof: MerkleSparseTreePath<TC>,
    block_tree_root: <BlockTreeConfig<C> as Config>::InnerDigest,
    block_inclusion_proof: MerkleSparseTreePath<BlockTreeConfig<C>>,
    nullifier: Nullifier<C::BaseField>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, TC: SparseConfig, SC: SparseConfig>
    UTXOProof<C, TC, SC>
{
    pub fn new(
        block: Block<C::BaseField>,
        tx: ShieldedTransaction<C>,
        tx_index: C::BaseField,
        utxo: UTXO<C>,
        utxo_index: C::BaseField,
        utxo_inclusion_proof: Path<ShieldedTransactionConfig<C>>,
        signer_inclusion_proof: MerkleSparseTreePath<SC>,
        tx_inclusion_proof: MerkleSparseTreePath<TC>,
        block_tree_root: <BlockTreeConfig<C> as Config>::InnerDigest,
        block_inclusion_proof: MerkleSparseTreePath<BlockTreeConfig<C>>,
        nullifier: Nullifier<C::BaseField>,
    ) -> Self {
        UTXOProof {
            block,
            tx,
            tx_index,
            utxo,
            utxo_index,
            utxo_inclusion_proof,
            signer_inclusion_proof,
            tx_inclusion_proof,
            block_tree_root,
            block_inclusion_proof,
            nullifier,
        }
    }
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
    shielded_tx_outputs_proofs: &[PathVar<
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
                .outputs
                .iter()
                .map(|i| &i.amount)
                .sum::<FpVar<C::BaseField>>(),
        )?;

    for input_utxo_proof in input_utxos_proofs {
        input_utxo_proof.is_valid(null_sk, pk.clone(), &plasma_blind_config)?;
    }

    // initialize variables to ensure that output utxos have a strictly increasing index starting
    // at TX_IO_SIZE
    let one = FpVar::new_constant(cs.clone(), C::BaseField::one())?;
    let mut index_output_utxo =
        FpVar::new_constant(cs.clone(), C::BaseField::from((TX_IO_SIZE) as u64))?;

    for (shielded_tx_inclusion_proof, output_utxo) in
        shielded_tx_outputs_proofs.iter().zip(shielded_tx_outputs)
    {
        // ensure that utxo indexes are correct
        output_utxo.index.enforce_equal(&index_output_utxo)?;
        let is_in_tx = shielded_tx_inclusion_proof.verify_membership(
            &plasma_blind_config.shielded_tx_leaf_config,
            &plasma_blind_config.shielded_tx_two_to_one_config,
            &shielded_tx.shielded_tx,
            output_utxo,
        )?;

        is_in_tx.enforce_equal(&Boolean::Constant(true))?;
        index_output_utxo += one.clone();
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;
    use ark_serialize::Compress;
    use std::collections::BTreeMap;

    use ark_crypto_primitives::{
        crh::{
            CRHScheme, TwoToOneCRHScheme,
            poseidon::{CRH, TwoToOneCRH},
        },
        merkle_tree::{Path, constraints::PathVar},
        sponge::Absorb,
    };

    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_grumpkin::constraints::GVar as GrumpkinProjectiveVar;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::alloc::AllocationMode;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;

    use crate::primitives::crh::utils::initialize_two_to_one_binary_tree_poseidon_config;
    use crate::{
        Nullifier, UTXOProof, UTXOProofVar,
        config::{PlasmaBlindConfig, PlasmaBlindConfigVar},
        datastructures::{
            TX_IO_SIZE,
            block::Block,
            keypair::constraints::PublicKeyVar,
            shieldedtx::{
                ShieldedTransaction,
                constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
            },
            signerlist::{SignerTreeConfig, constraints::SignerTreeConfigGadget},
            transparenttx::{TransparentTransaction, constraints::TransparentTransactionVar},
            txtree::{TransactionTreeConfig, constraints::TransactionTreeConfigGadget},
            user::User,
            utxo::constraints::UTXOVar,
        },
        primitives::{
            crh::{
                BlockCRH, BlockTreeCRH, PublicKeyCRH, ShieldedTransactionCRH, UTXOCRH,
                utils::initialize_poseidon_config,
            },
            sparsemt::{MerkleSparseTree, SparseConfig},
        },
        tx_validity_circuit,
    };

    pub fn make_sparse_tree<
        F: PrimeField + Absorb,
        MT: SparseConfig<InnerDigest = F, LeafDigest = F, TwoToOneHash = TwoToOneCRH<F>>,
    >(
        leaf_hash_params: &<MT::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        values: impl Iterator<Item = MT::Leaf>,
    ) -> MerkleSparseTree<MT> {
        let mut leaves = BTreeMap::new();
        for (i, value) in values.into_iter().enumerate() {
            leaves.insert(i as u64, value);
        }
        MerkleSparseTree::<MT>::new(leaf_hash_params, two_to_one_hash_params, &leaves).unwrap()
    }

    #[test]
    fn test_validity_circuit() {
        let mut rng = test_rng();

        // initialize our plasma blind config
        // poseidon crh only for now, should be configurable in the future
        let two_to_one_poseidon_config = initialize_two_to_one_binary_tree_poseidon_config::<Fr>();
        let poseidon_config = initialize_poseidon_config::<Fr>();

        let shielded_tx_leaf_config =
            <UTXOCRH<GrumpkinProjective> as CRHScheme>::setup(&mut rng).unwrap();
        let tx_tree_leaf_config =
            <ShieldedTransactionCRH<GrumpkinProjective> as CRHScheme>::setup(&mut rng).unwrap();
        let signer_tree_leaf_config =
            <PublicKeyCRH<GrumpkinProjective> as CRHScheme>::setup(&mut rng).unwrap();
        let block_tree_leaf_config = <BlockTreeCRH<Fr> as CRHScheme>::setup(&mut rng).unwrap();

        let tx_tree_two_to_one_config = two_to_one_poseidon_config.clone();
        let shielded_tx_two_to_one_config = two_to_one_poseidon_config.clone();
        let signer_tree_two_to_one_config = two_to_one_poseidon_config.clone();
        let block_tree_two_to_one_config = two_to_one_poseidon_config.clone();

        let block_crh_config = <BlockCRH<Fr> as CRHScheme>::setup(&mut rng).unwrap();

        let config = PlasmaBlindConfig::<
            GrumpkinProjective,
            TransactionTreeConfig<GrumpkinProjective>,
            SignerTreeConfig<GrumpkinProjective>,
        >::new(
            poseidon_config.clone(),
            shielded_tx_leaf_config,
            shielded_tx_two_to_one_config,
            tx_tree_leaf_config,
            tx_tree_two_to_one_config,
            signer_tree_leaf_config,
            signer_tree_two_to_one_config,
            block_crh_config,
            block_tree_leaf_config,
            block_tree_two_to_one_config,
        );

        // 1. Define users
        // we will implement the following flow: alice -> bob -> alice
        let alice = User::<GrumpkinProjective>::new(&mut rng, 1);
        let alice_sk = Fr::rand(&mut rng);
        let bob = User::<GrumpkinProjective>::new(&mut rng, 2);
        let bob_sk = Fr::rand(&mut rng);
        let bob_pk = CRH::evaluate(&config.poseidon_config, vec![bob_sk]).unwrap();

        // 2. prepare alice's transaction
        // NOTE: tx_index and block_height get assigned by the aggregator and the L1
        // respectively
        let alice_to_bob_tx_index = 1;
        let block_height = 0;

        // NOTE: alice to bob utxo will be placed at the latest position in the transaction
        let mut alice_to_bob_tx = TransparentTransaction::default();
        alice_to_bob_tx.outputs[TX_IO_SIZE - 1].pk = bob.keypair.pk;
        alice_to_bob_tx.outputs[TX_IO_SIZE - 1].amount = 10;
        alice_to_bob_tx.outputs[TX_IO_SIZE - 1].tx_index = Some(alice_to_bob_tx_index);
        alice_to_bob_tx.outputs[TX_IO_SIZE - 1].block_height = Some(block_height);

        let (alice_to_bob_shielded_tx, alice_to_bob_shielded_tx_tree) = ShieldedTransaction::new(
            &config.shielded_tx_leaf_config,
            &config.shielded_tx_two_to_one_config,
            alice.keypair.pk,
            &alice_to_bob_tx,
        )
        .unwrap();
        let alice_to_bob_tx_nullifiers = alice_to_bob_tx
            .nullifiers(&config.poseidon_config, &alice_sk)
            .unwrap();

        // 3. build block where alice's transaction is included
        let mut transactions_in_block = [ShieldedTransaction::default(); 8];
        transactions_in_block[alice_to_bob_tx_index as usize] = alice_to_bob_shielded_tx.clone();

        // NOTE: transactions and signer tree are built by the aggregator
        let transactions_tree = make_sparse_tree(
            &config.tx_tree_leaf_config,
            &config.tx_tree_two_to_one_config,
            transactions_in_block.into_iter(),
        );
        // alice's keypair will be stored at index 0 in the signer tree
        let signer_tree = make_sparse_tree(
            &config.signer_tree_leaf_config,
            &config.signer_tree_two_to_one_config,
            [alice.keypair.pk.clone()].into_iter(),
        );
        let prev_block = Block {
            tx_tree_root: transactions_tree.root(),
            signer_tree_root: signer_tree.root(),
            nullifiers: alice_to_bob_tx_nullifiers,
            signers: vec![Some(alice.id)],
            height: block_height as usize,
            deposits: vec![],
            withdrawals: vec![],
        };

        // NOTE: block tree stored on the l1
        let block_hash = BlockCRH::evaluate(&config.block_crh_config, prev_block.clone()).unwrap();
        let block_tree = make_sparse_tree(
            &(),
            &config.block_tree_two_to_one_config,
            [block_hash].into_iter(),
        );

        // 3. alice provides bob with the utxo, a proof of inclusion of the tx and a proof of inclusion for
        //    the utxo, which is the last leaf of the shielded transaction tree.
        //    NOTE: this is happening OOB
        let alice_to_bob_utxo = alice_to_bob_tx.outputs[TX_IO_SIZE - 1];
        let alice_to_bob_utxo_index = alice_to_bob_utxo.index;
        let alice_to_bob_utxo_proof = alice_to_bob_shielded_tx_tree
            .generate_proof(alice_to_bob_utxo_index as usize)
            .unwrap();
        let alice_shielded_tx_inclusion_proof = transactions_tree
            .generate_membership_proof(alice_to_bob_tx_index)
            .unwrap();

        // 4. signer and block inclusion proof are retrieved by bob from the l1
        let alice_signer_inclusion_proof = signer_tree.generate_membership_proof(0).unwrap();
        let block_inclusion_proof = block_tree.generate_membership_proof(0).unwrap();

        // 5. prepare bob to alice transaction utxos. first utxo input is alice's utxo to bob
        // the last utxo output is bob's utxo to alice
        let mut bob_to_alice_tx = TransparentTransaction::default();
        bob_to_alice_tx.inputs[0] = alice_to_bob_utxo;
        bob_to_alice_tx.outputs[TX_IO_SIZE - 1].pk = alice.keypair.pk;
        bob_to_alice_tx.outputs[TX_IO_SIZE - 1].amount = 10;

        // 6. prepare bob to alice shielded transaction
        let (bob_to_alice_shielded_tx, bob_to_alice_shielded_tx_tree) = ShieldedTransaction::new(
            &config.shielded_tx_leaf_config,
            &config.shielded_tx_two_to_one_config,
            bob.keypair.pk,
            &bob_to_alice_tx,
        )
        .unwrap();

        let bob_to_alice_shielded_tx_output_proofs = (4..8)
            .map(|i| bob_to_alice_shielded_tx_tree.generate_proof(i).unwrap())
            .collect::<Vec<Path<_>>>();

        // 7. prepare proof for the input utxo from alice
        let alice_to_bob_utxo_nullifier = Nullifier::new(
            &config.poseidon_config,
            bob_sk,
            alice_to_bob_utxo_index as u8,
            alice_to_bob_tx_index as usize,
            block_height as usize,
        )
        .unwrap();

        let mut bob_input_utxos_proofs = vec![UTXOProof::default(); 4];

        let utxo_from_alice_proof = UTXOProof::new(
            prev_block,
            alice_to_bob_shielded_tx,
            Fr::from(alice_to_bob_tx_index),
            alice_to_bob_utxo,
            Fr::from(alice_to_bob_utxo_index as u8),
            alice_to_bob_utxo_proof,
            alice_signer_inclusion_proof,
            alice_shielded_tx_inclusion_proof,
            block_tree.root(),
            block_inclusion_proof,
            alice_to_bob_utxo_nullifier,
        );
        bob_input_utxos_proofs[0] = utxo_from_alice_proof;

        // 8. initialize cs and inputs
        let cs = ConstraintSystem::<Fr>::new_ref();

        // define public input values
        let null_pk_var = FpVar::new_input(cs.clone(), || Ok(bob_pk)).unwrap();
        let bob_pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(bob.keypair.pk)).unwrap();
        let bob_to_alice_shielded_tx_var =
            ShieldedTransactionVar::new_input(cs.clone(), || Ok(bob_to_alice_shielded_tx)).unwrap();

        // define input witness values
        let null_sk_var = FpVar::new_witness(cs.clone(), || Ok(bob_sk)).unwrap();
        let bob_to_alice_transparent_tx_var =
            TransparentTransactionVar::new_witness(cs.clone(), || Ok(bob_to_alice_tx.clone()))
                .unwrap();
        let bob_to_alice_shielded_tx_outputs_var =
            Vec::<UTXOVar<_, GrumpkinProjectiveVar>>::new_witness(cs.clone(), || {
                Ok(bob_to_alice_tx.outputs.clone())
            })
            .unwrap();
        let bob_to_alice_shielded_tx_output_proofs_var = Vec::<
            PathVar<_, _, ShieldedTransactionConfigGadget<_, GrumpkinProjectiveVar>>,
        >::new_witness(cs.clone(), || {
            Ok(bob_to_alice_shielded_tx_output_proofs)
        })
        .unwrap();
        let bob_input_utxo_proofs_var =
            Vec::<UTXOProofVar<_, GrumpkinProjectiveVar, _, _, _, _>>::new_witness(
                cs.clone(),
                || Ok(bob_input_utxos_proofs.clone()),
            )
            .unwrap();

        let config_var =
            PlasmaBlindConfigVar::<
                _,
                GrumpkinProjectiveVar,
                _,
                TransactionTreeConfigGadget<_, GrumpkinProjectiveVar>,
                _,
                SignerTreeConfigGadget<_, GrumpkinProjectiveVar>,
            >::new_variable(cs.clone(), || Ok(config), AllocationMode::Constant)
            .unwrap();

        tx_validity_circuit(
            cs.clone(),
            &null_sk_var,
            &null_pk_var,
            bob_pk_var,
            &bob_to_alice_transparent_tx_var,
            &bob_to_alice_shielded_tx_var,
            &bob_to_alice_shielded_tx_outputs_var,
            &bob_to_alice_shielded_tx_output_proofs_var,
            &bob_input_utxo_proofs_var,
            &config_var,
        )
        .unwrap();

        cs.finalize();

        assert!(cs.is_satisfied().unwrap());
        let wtns = cs.witness_assignment().unwrap();

        println!("n constraints: {}", cs.num_constraints());
        println!("n wtns elements: {}", wtns.len());
        println!(
            "wtns size uncompressed: {}",
            wtns.serialized_size(Compress::No)
        );
        println!(
            "wtns size compressed: {}",
            wtns.serialized_size(Compress::Yes)
        );
    }
}

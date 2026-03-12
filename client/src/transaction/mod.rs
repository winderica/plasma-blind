use ark_crypto_primitives::{
    crh::{poseidon::constraints::CRHGadget, CRHSchemeGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use plasmablind_core::{
    config::{PlasmaBlindConfig, PlasmaBlindConfigVar},
    datastructures::{
        shieldedtx::{constraints::ShieldedTransactionVar, ShieldedTransaction},
        transparenttx::{constraints::TransparentTransactionVar, TransparentTransaction},
        utxo::proof::{constraints::UTXOProofVar, UTXOProof},
        TX_IO_SIZE,
    },
    primitives::crh::{constraints::UTXOVarCRH, utils::Init},
};
use sonobe_primitives::transcripts::Absorbable;

#[derive(Clone)]
pub struct TransactionValidityCircuit<Cfg: Init> {
    null_sk: Cfg::F, // user secret for nullifier computation
    null_pk: Cfg::F, // hash of user's secret, which is registered on the L1
    transparent_tx: TransparentTransaction<Cfg::F>, // transparent transaction
    shielded_tx: ShieldedTransaction<Cfg::F>, // shielded transaction (root of tree built from
    // transparent tx)
    block_tree_root: Cfg::F,
    input_utxos_proofs: Vec<UTXOProof<Cfg>>, // proof of existence of input
    // utxos
    plasma_blind_config: PlasmaBlindConfig<Cfg>,
}

impl<Cfg: Init> TransactionValidityCircuit<Cfg> {
    pub fn new(
        null_sk: Cfg::F, // user secret for nullifier computation
        null_pk: Cfg::F, // hash of user's secret, which is registered on the L1
        transparent_tx: TransparentTransaction<Cfg::F>, // transparent transaction
        shielded_tx: ShieldedTransaction<Cfg::F>, // shielded transaction (root of tree built from
        // transparent tx)
        block_tree_root: Cfg::F,
        input_utxos_proofs: Vec<UTXOProof<Cfg>>, // proof of existence of input
        // utxos
        plasma_blind_config: PlasmaBlindConfig<Cfg>,
    ) -> Self {
        TransactionValidityCircuit {
            null_sk,
            null_pk,
            transparent_tx,
            shielded_tx,
            block_tree_root,
            input_utxos_proofs,
            plasma_blind_config,
        }
    }
}

impl<Cfg: Init> ConstraintSynthesizer<Cfg::F> for TransactionValidityCircuit<Cfg> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Cfg::F>) -> Result<(), SynthesisError> {
        let null_sk = FpVar::new_witness(cs.clone(), || Ok(self.null_sk))?;
        let null_pk = FpVar::new_input(cs.clone(), || Ok(self.null_pk))?;
        let transparent_tx =
            TransparentTransactionVar::new_witness(cs.clone(), || Ok(self.transparent_tx.clone()))?;
        let shielded_tx =
            ShieldedTransactionVar::<_>::new_input(cs.clone(), || Ok(self.shielded_tx))?;
        let block_tree_root = FpVar::new_input(cs.clone(), || Ok(self.block_tree_root))?;

        let input_utxos_proofs =
            Vec::<UTXOProofVar<_>>::new_witness(cs.clone(), || Ok(self.input_utxos_proofs))?;

        let plasma_blind_config = PlasmaBlindConfigVar::new_variable(
            cs.clone(),
            || Ok(self.plasma_blind_config),
            AllocationMode::Constant,
        )?;

        let null_pk_computed =
            Cfg::HGadget::evaluate(&plasma_blind_config.hash_config, &[null_sk.clone()])?;
        null_pk_computed.enforce_equal(&null_pk)?;

        // checks transparent tx inputs sum up to outputs
        transparent_tx.enforce_valid(&null_pk)?;

        for i in 0..TX_IO_SIZE {
            transparent_tx.inputs[i].is_valid(
                &null_sk,
                &shielded_tx.input_nullifiers[i],
                &transparent_tx.inputs_info[i],
                &input_utxos_proofs[i],
                &block_tree_root,
                &plasma_blind_config,
            )?;

            shielded_tx.output_utxo_commitments[i].enforce_equal(
                &transparent_tx.outputs[i].is_dummy.select(
                    &FpVar::zero(),
                    &UTXOVarCRH::<Cfg>::evaluate(
                        &plasma_blind_config.utxo_crh_config,
                        &transparent_tx.outputs[i],
                    )?,
                )?,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::{collections::BTreeMap, sync::Arc, time::Instant};

    use ark_bn254::{Fr, G1Projective};
    use ark_crypto_primitives::{
        crh::{poseidon::CRH, CRHScheme},
        sponge::poseidon::PoseidonConfig,
    };
    use ark_ff::UniformRand;
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_std::test_rng;
    use sonobe_fs::{
        nova::{
            instances::{IncomingInstance, RunningInstance},
            witnesses::{IncomingWitness, RunningWitness},
            Nova,
        },
        DeciderKey, FoldingSchemeDef, FoldingSchemeKeyGenerator, FoldingSchemePreprocessor,
        FoldingSchemeProver,
    };
    use sonobe_primitives::{
        circuits::{Assignments, ConstraintSystemBuilder},
        commitments::pedersen::Pedersen,
        relations::WitnessInstanceSampler,
        transcripts::{
            griffin::{sponge::GriffinSponge, GriffinParams},
            Transcript,
        },
    };

    use plasmablind_core::{
        config::PlasmaBlindConfig,
        datastructures::{
            block::BlockMetadata,
            blocktree::{SparseNAryBlockTree, BLOCK_TREE_ARITY, NARY_BLOCK_TREE_HEIGHT},
            shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
            signerlist::{SparseNArySignerTree, SIGNER_TREE_ARITY},
            transparenttx::TransparentTransaction,
            txtree::{SparseNAryTransactionTree, TRANSACTION_TREE_ARITY},
            utxo::{proof::UTXOProof, UTXOInfo, UTXO},
            TX_IO_SIZE,
        },
        primitives::{
            crh::{utils::Init, BlockTreeCRH, IntervalCRH, UTXOCRH},
            sparsemt::MerkleSparseTree,
        },
    };

    fn test_validity_circuit_opt<Cfg: Init<F = Fr>>() {
        let mut rng = test_rng();

        println!(
            "BLOCK_TREE_ARITY: {BLOCK_TREE_ARITY}, BLOCK_TREE_HEIGHT: {NARY_BLOCK_TREE_HEIGHT}"
        );

        let hash_config = Cfg::init::<2>();

        let utxo_crh_config = UTXOCRH::<Cfg>::setup(&mut rng).unwrap();
        let shielded_tx_leaf_config = ();
        let tx_tree_leaf_config = ();
        let signer_tree_leaf_config = ();
        let nullifier_tree_leaf_config = IntervalCRH::<Cfg>::setup(&mut rng).unwrap();
        let block_tree_leaf_config = BlockTreeCRH::<Cfg>::setup(&mut rng).unwrap();

        let shielded_tx_two_to_one_config = Cfg::init::<2>();
        let nullifier_tree_two_to_one_config = Cfg::init::<2>();
        let block_tree_n_to_one_config = Cfg::init::<BLOCK_TREE_ARITY>();
        let tx_tree_n_to_one_config = Cfg::init::<TRANSACTION_TREE_ARITY>();
        let signer_tree_n_to_one_config = Cfg::init::<SIGNER_TREE_ARITY>();

        let config = PlasmaBlindConfig::new(
            hash_config.clone(),
            utxo_crh_config,
            shielded_tx_leaf_config,
            shielded_tx_two_to_one_config,
            tx_tree_leaf_config,
            tx_tree_n_to_one_config,
            signer_tree_leaf_config,
            signer_tree_n_to_one_config,
            nullifier_tree_leaf_config,
            nullifier_tree_two_to_one_config,
            block_tree_leaf_config.clone(),
            block_tree_n_to_one_config.clone(),
        );

        // 1. Define users
        // we will implement the following flow: alice -> bob -> alice
        let alice_sk = Fr::rand(&mut rng);
        let alice_pk = Cfg::H::evaluate(&config.hash_config, vec![alice_sk]).unwrap();
        let bob_sk = Fr::rand(&mut rng);
        let bob_pk = Cfg::H::evaluate(&config.hash_config, vec![bob_sk]).unwrap();

        // 2. prepare alice's transaction
        // NOTE: tx_index and block_height get assigned by the aggregator and the L1
        // respectively
        let alice_to_bob_utxo_index = TX_IO_SIZE - 1;
        let alice_to_bob_tx_index = 1;
        let block_height = 0;

        // NOTE: alice to bob utxo will be placed at the latest position in the transaction
        let mut alice_to_bob_tx = TransparentTransaction::default();
        let alice_to_bob_utxo = UTXO::new(bob_pk, 10, Fr::rand(&mut rng));
        alice_to_bob_tx.set_output(alice_to_bob_utxo_index, alice_to_bob_utxo);

        let alice_to_bob_shielded_tx = ShieldedTransaction::new(
            &config.hash_config,
            &config.utxo_crh_config,
            &alice_sk,
            &alice_to_bob_tx,
        )
        .unwrap();
        let alice_to_bob_utxo_tree = MerkleSparseTree::<ShieldedTransactionConfig<_>>::new(
            &config.shielded_tx_leaf_config,
            &config.shielded_tx_two_to_one_config,
            &BTreeMap::from_iter(
                alice_to_bob_shielded_tx
                    .output_utxo_commitments
                    .into_iter()
                    .enumerate(),
            ),
        )
        .unwrap();

        // 3. build block where alice's transaction is included
        let mut transactions_in_block = vec![Fr::default(); 8];
        transactions_in_block[alice_to_bob_tx_index] = alice_to_bob_utxo_tree.root();
        let mut signers_in_block = vec![Fr::default(); 8];
        signers_in_block[alice_to_bob_tx_index] = alice_pk;

        // NOTE: transactions and signer tree are built by the aggregator
        let transactions_tree = SparseNAryTransactionTree::new(
            &config.tx_tree_leaf_config,
            &config.tx_tree_n_to_one_config,
            &BTreeMap::from_iter(transactions_in_block.into_iter().enumerate()),
            &Fr::default(),
        )
        .unwrap();

        let signer_tree = SparseNArySignerTree::new(
            &config.signer_tree_leaf_config,
            &config.signer_tree_n_to_one_config,
            &BTreeMap::from_iter(signers_in_block.into_iter().enumerate()),
            &Fr::default(),
        )
        .unwrap();
        let prev_block = BlockMetadata {
            tx_tree_root: transactions_tree.root(),
            signer_tree_root: signer_tree.root(),
            nullifier_tree_root: Fr::default(),
            height: block_height,
        };

        // NOTE: block tree stored on the l1
        let block_tree = SparseNAryBlockTree::new(
            &block_tree_leaf_config,
            &block_tree_n_to_one_config,
            &BTreeMap::from_iter([prev_block.clone()].into_iter().enumerate()),
            &BlockMetadata::default(),
        )
        .unwrap();

        // 3. alice provides bob with the utxo, a proof of inclusion of the tx and a proof of inclusion for
        //    the utxo, which is the last leaf of the shielded transaction tree.
        //    NOTE: this is happening OOB
        let alice_to_bob_utxo_info = UTXOInfo {
            utxo_index: alice_to_bob_utxo_index,
            tx_index: alice_to_bob_tx_index,
            block_height,
            from: alice_pk,
        };
        let alice_to_bob_utxo_proof = alice_to_bob_utxo_tree
            .generate_membership_proof(alice_to_bob_utxo_info.utxo_index)
            .unwrap();

        let alice_shielded_tx_inclusion_proof = transactions_tree
            .generate_proof(alice_to_bob_utxo_info.tx_index)
            .unwrap();

        // 4. signer and block inclusion proof are retrieved by bob from the l1
        let alice_signer_inclusion_proof = signer_tree
            .generate_proof(alice_to_bob_utxo_info.tx_index)
            .unwrap();

        let block_inclusion_proof = block_tree
            .generate_proof(alice_to_bob_utxo_info.block_height)
            .unwrap();

        assert!(block_inclusion_proof
            .verify(
                &block_tree.leaf_hash_param,
                &block_tree_n_to_one_config.clone(),
                &block_tree.root(),
                prev_block.clone(),
            )
            .unwrap());

        // 5. prepare bob to alice transaction utxos. first utxo input is alice's utxo to bob
        // the last utxo output is bob's utxo to alice
        let mut bob_to_alice_tx = TransparentTransaction::default();
        bob_to_alice_tx.set_input(0, alice_to_bob_utxo, alice_to_bob_utxo_info);
        bob_to_alice_tx.set_output(
            alice_to_bob_utxo_index,
            UTXO::new(bob_pk, 10, Fr::rand(&mut rng)),
        );

        // 6. prepare bob to alice shielded transaction
        let bob_to_alice_shielded_tx = ShieldedTransaction::new(
            &config.hash_config,
            &config.utxo_crh_config,
            &bob_sk,
            &bob_to_alice_tx,
        )
        .unwrap();

        // 7. prepare proof for the input utxo from alice
        let mut bob_input_utxos_proofs = vec![UTXOProof::default(); TX_IO_SIZE];

        let utxo_from_alice_proof = UTXOProof::new(
            prev_block,
            alice_to_bob_utxo_proof,
            alice_signer_inclusion_proof,
            alice_shielded_tx_inclusion_proof,
            block_inclusion_proof.clone(),
        );
        bob_input_utxos_proofs[0] = utxo_from_alice_proof;

        let tx_validity_circuit = TransactionValidityCircuit::new(
            bob_sk,
            bob_pk,
            bob_to_alice_tx.clone(),
            bob_to_alice_shielded_tx,
            block_tree.root(),
            bob_input_utxos_proofs,
            config,
        );

        let cs_ref = ConstraintSystem::new_ref();

        let start = Instant::now();
        tx_validity_circuit
            .clone()
            .generate_constraints(cs_ref.clone())
            .unwrap();
        let elapsed = start.elapsed();
        println!("Synthesizing took: {:?}", elapsed);

        let (w, x) = (
            cs_ref.witness_assignment().unwrap(),
            cs_ref
                .instance_assignment()
                .unwrap()
                .into_iter()
                .skip(1)
                .collect(),
        );
        assert!(cs_ref.is_satisfied().unwrap());

        let cs = ConstraintSystemBuilder::new()
            .with_prove_mode()
            .with_circuit(tx_validity_circuit)
            .synthesize()
            .unwrap();
        let ck_size = cs.num_constraints().max(cs.num_witness_variables());

        let assignments = Assignments::from((Fr::from(1), x, w));
        let arith = <Nova<Pedersen<G1Projective, true>> as FoldingSchemeDef>::Arith::from(cs);
        let pp_f = Nova::<Pedersen<G1Projective, true>>::preprocess(ck_size, &mut rng).unwrap();
        let dk = Nova::<Pedersen<G1Projective, true>>::generate_keys(pp_f, arith).unwrap();
        let (W, U): (
            RunningWitness<Pedersen<G1Projective, true>>,
            RunningInstance<Pedersen<G1Projective, true>>,
        ) = dk.sample((), &mut rng).unwrap();
        let (w, u): (
            IncomingWitness<Pedersen<G1Projective, true>>,
            IncomingInstance<Pedersen<G1Projective, true>>,
        ) = dk.sample(assignments, &mut rng).unwrap();

        let hash_config = Arc::new(GriffinParams::new(16, 5, 9));
        let hash = GriffinSponge::<Fr>::new_with_pp_hash(&hash_config, Default::default());
        let mut transcript = hash.separate_domain("transcript1".as_ref());

        let start = Instant::now();
        let (rw, ru, cm_t, rho) = Nova::<Pedersen<G1Projective, true>>::prove(
            dk.to_pk(),
            &mut transcript,
            &[W],
            &[U],
            &[w],
            &[u],
            &mut rng,
        )
        .unwrap();
        let elapsed = start.elapsed();
        println!("Proving took: {:?}", elapsed);

        let (len_wtns, size) = (rw.w.len(), rw.w.serialized_size(Compress::Yes));
        println!("len wtns: {len_wtns}, compressed_size: {size}");
    }

    #[test]
    fn test_validity_circuit() {
        test_validity_circuit_opt::<PoseidonConfig<Fr>>();
        test_validity_circuit_opt::<GriffinParams<Fr>>();
    }

    /// Computes and prints the client-side proof size for the current
    /// `BLOCK_TREE_HEIGHT` and `TX_IO_SIZE` configuration.
    ///
    /// Run with different env vars to collect data for charts:
    /// ```sh
    /// BLOCK_TREE_HEIGHT=4 cargo test -p client -- test_proof_size --nocapture
    /// BLOCK_TREE_HEIGHT=32 TX_IO_SIZE=4 cargo test -p client -- test_proof_size --nocapture
    /// ```
    fn test_proof_size_opt<Cfg: Init<F = Fr>>(hash_name: &str) {
        let mut rng = test_rng();

        let hash_config = Cfg::init::<2>();
        let utxo_crh_config = UTXOCRH::<Cfg>::setup(&mut rng).unwrap();
        let shielded_tx_leaf_config = ();
        let tx_tree_leaf_config = ();
        let signer_tree_leaf_config = ();
        let nullifier_tree_leaf_config = IntervalCRH::<Cfg>::setup(&mut rng).unwrap();
        let block_tree_leaf_config = BlockTreeCRH::<Cfg>::setup(&mut rng).unwrap();

        let shielded_tx_two_to_one_config = Cfg::init::<2>();
        let nullifier_tree_two_to_one_config = Cfg::init::<2>();
        let block_tree_n_to_one_config = Cfg::init::<BLOCK_TREE_ARITY>();
        let tx_tree_n_to_one_config = Cfg::init::<TRANSACTION_TREE_ARITY>();
        let signer_tree_n_to_one_config = Cfg::init::<SIGNER_TREE_ARITY>();

        let config = PlasmaBlindConfig::new(
            hash_config.clone(),
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
        );

        let alice_sk = Fr::rand(&mut rng);
        let alice_pk = Cfg::H::evaluate(&config.hash_config, vec![alice_sk]).unwrap();
        let bob_sk = Fr::rand(&mut rng);
        let bob_pk = Cfg::H::evaluate(&config.hash_config, vec![bob_sk]).unwrap();

        let alice_to_bob_utxo_index = TX_IO_SIZE - 1;
        let alice_to_bob_tx_index = 1;
        let block_height = 0;

        let mut alice_to_bob_tx = TransparentTransaction::default();
        let alice_to_bob_utxo = UTXO::new(bob_pk, 10, Fr::rand(&mut rng));
        alice_to_bob_tx.set_output(alice_to_bob_utxo_index, alice_to_bob_utxo);

        let alice_to_bob_shielded_tx = ShieldedTransaction::new(
            &config.hash_config,
            &config.utxo_crh_config,
            &alice_sk,
            &alice_to_bob_tx,
        )
        .unwrap();
        let alice_to_bob_utxo_tree = MerkleSparseTree::<ShieldedTransactionConfig<_>>::new(
            &config.shielded_tx_leaf_config,
            &config.shielded_tx_two_to_one_config,
            &BTreeMap::from_iter(
                alice_to_bob_shielded_tx
                    .output_utxo_commitments
                    .into_iter()
                    .enumerate(),
            ),
        )
        .unwrap();

        let mut transactions_in_block = vec![Fr::default(); 8];
        transactions_in_block[alice_to_bob_tx_index] = alice_to_bob_utxo_tree.root();
        let mut signers_in_block = vec![Fr::default(); 8];
        signers_in_block[alice_to_bob_tx_index] = alice_pk;

        let transactions_tree = SparseNAryTransactionTree::new(
            &config.tx_tree_leaf_config,
            &config.tx_tree_n_to_one_config,
            &BTreeMap::from_iter(transactions_in_block.into_iter().enumerate()),
            &Fr::default(),
        )
        .unwrap();

        let signer_tree = SparseNArySignerTree::new(
            &config.signer_tree_leaf_config,
            &config.signer_tree_n_to_one_config,
            &BTreeMap::from_iter(signers_in_block.into_iter().enumerate()),
            &Fr::default(),
        )
        .unwrap();
        let prev_block = BlockMetadata {
            tx_tree_root: transactions_tree.root(),
            signer_tree_root: signer_tree.root(),
            nullifier_tree_root: Fr::default(),
            height: block_height,
        };

        let block_tree = SparseNAryBlockTree::new(
            &config.block_tree_leaf_config,
            &config.block_tree_n_to_one_config,
            &BTreeMap::from_iter([prev_block.clone()].into_iter().enumerate()),
            &BlockMetadata::default(),
        )
        .unwrap();

        let alice_to_bob_utxo_info = UTXOInfo {
            utxo_index: alice_to_bob_utxo_index,
            tx_index: alice_to_bob_tx_index,
            block_height,
            from: alice_pk,
        };
        let alice_to_bob_utxo_proof = alice_to_bob_utxo_tree
            .generate_membership_proof(alice_to_bob_utxo_info.utxo_index)
            .unwrap();

        let alice_shielded_tx_inclusion_proof = transactions_tree
            .generate_proof(alice_to_bob_utxo_info.tx_index)
            .unwrap();

        let alice_signer_inclusion_proof = signer_tree
            .generate_proof(alice_to_bob_utxo_info.tx_index)
            .unwrap();

        let block_inclusion_proof = block_tree
            .generate_proof(alice_to_bob_utxo_info.block_height)
            .unwrap();

        let mut bob_to_alice_tx = TransparentTransaction::default();
        bob_to_alice_tx.set_input(0, alice_to_bob_utxo, alice_to_bob_utxo_info);
        bob_to_alice_tx.set_output(
            alice_to_bob_utxo_index,
            UTXO::new(bob_pk, 10, Fr::rand(&mut rng)),
        );

        let bob_to_alice_shielded_tx = ShieldedTransaction::new(
            &config.hash_config,
            &config.utxo_crh_config,
            &bob_sk,
            &bob_to_alice_tx,
        )
        .unwrap();

        let mut bob_input_utxos_proofs = vec![UTXOProof::default(); TX_IO_SIZE];
        bob_input_utxos_proofs[0] = UTXOProof::new(
            prev_block,
            alice_to_bob_utxo_proof,
            alice_signer_inclusion_proof,
            alice_shielded_tx_inclusion_proof,
            block_inclusion_proof,
        );

        let tx_validity_circuit = TransactionValidityCircuit::new(
            bob_sk,
            bob_pk,
            bob_to_alice_tx,
            bob_to_alice_shielded_tx,
            block_tree.root(),
            bob_input_utxos_proofs,
            config,
        );

        // Synthesize and generate Nova proof
        let cs_ref = ConstraintSystem::new_ref();
        tx_validity_circuit
            .clone()
            .generate_constraints(cs_ref.clone())
            .unwrap();
        assert!(cs_ref.is_satisfied().unwrap());

        let (w, x) = (
            cs_ref.witness_assignment().unwrap(),
            cs_ref
                .instance_assignment()
                .unwrap()
                .into_iter()
                .skip(1)
                .collect(),
        );

        let cs = ConstraintSystemBuilder::new()
            .with_prove_mode()
            .with_circuit(tx_validity_circuit)
            .synthesize()
            .unwrap();
        let ck_size = cs.num_constraints().max(cs.num_witness_variables());

        let assignments = Assignments::from((Fr::from(1), x, w));
        let arith = <Nova<Pedersen<G1Projective, true>> as FoldingSchemeDef>::Arith::from(cs);
        let pp_f = Nova::<Pedersen<G1Projective, true>>::preprocess(ck_size, &mut rng).unwrap();
        let dk = Nova::<Pedersen<G1Projective, true>>::generate_keys(pp_f, arith).unwrap();
        let (W, U): (
            RunningWitness<Pedersen<G1Projective, true>>,
            RunningInstance<Pedersen<G1Projective, true>>,
        ) = dk.sample((), &mut rng).unwrap();
        let (w, u): (
            IncomingWitness<Pedersen<G1Projective, true>>,
            IncomingInstance<Pedersen<G1Projective, true>>,
        ) = dk.sample(assignments, &mut rng).unwrap();

        let hash_config_sponge = Arc::new(GriffinParams::new(16, 5, 9));
        let hash =
            GriffinSponge::<Fr>::new_with_pp_hash(&hash_config_sponge, Default::default());
        let mut transcript = hash.separate_domain("transcript1".as_ref());

        let (rw, _, _, _) = Nova::<Pedersen<G1Projective, true>>::prove(
            dk.to_pk(),
            &mut transcript,
            &[W],
            &[U],
            &[w],
            &[u],
            &mut rng,
        )
        .unwrap();

        // Measure proof size: the running witness dominates the proof sent to the aggregator.
        // The witness vector contains all R1CS assignments including Merkle path elements
        // that scale with block tree height. Instance and proof components are small and
        // constant w.r.t. block tree height, so we omit them.
        let total_size = rw.w.serialized_size(Compress::Yes);

        // CSV output: height,hash,io_size,proof_size_bytes
        println!(
            "PROOF_SIZE_CSV,{},{},{},{},{}",
            NARY_BLOCK_TREE_HEIGHT, hash_name, TX_IO_SIZE, total_size,
            total_size as f64 / 1024.0
        );
    }

    #[test]
    fn test_proof_size() {
        test_proof_size_opt::<PoseidonConfig<Fr>>("poseidon");
        test_proof_size_opt::<GriffinParams<Fr>>("griffin");
    }
}

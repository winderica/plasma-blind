pub mod circuit;
pub mod config;
pub mod datastructures;
pub mod errs;
pub mod primitives;
pub mod utils;

pub const NULLIFIER_TREE_HEIGHT: usize = 32;

#[cfg(test)]
pub mod tests {

    use std::{collections::BTreeMap, sync::Arc};

    use ark_bn254::{Fr, G1Projective};
    use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
    use ark_ff::UniformRand;

    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_std::test_rng;
    use sonobe_fs::{
        DeciderKey, FoldingSchemeDef, FoldingSchemeKeyGenerator, FoldingSchemePreprocessor,
        FoldingSchemeProver,
        nova::{
            Nova,
            instances::{IncomingInstance, RunningInstance},
            witnesses::{IncomingWitness, RunningWitness},
        },
    };
    use sonobe_primitives::{
        circuits::{Assignments, ConstraintSystemBuilder},
        commitments::pedersen::Pedersen,
        relations::WitnessInstanceSampler,
        transcripts::{
            Transcript,
            griffin::{GriffinParams, sponge::GriffinSponge},
        },
    };

    use crate::{
        circuit::TransactionValidityCircuit,
        config::PlasmaBlindConfig,
        datastructures::{
            TX_IO_SIZE,
            block::BlockMetadata,
            blocktree::{BLOCK_TREE_ARITY, SparseNAryBlockTree},
            shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
            signerlist::{SIGNER_TREE_ARITY, SignerTree, SparseNArySignerTree},
            transparenttx::TransparentTransaction,
            txtree::{SparseNAryTransactionTree, TRANSACTION_TREE_ARITY, TransactionTree},
            utxo::{UTXO, UTXOInfo, proof::UTXOProof},
        },
        primitives::{
            crh::{
                BlockTreeCRH, BlockTreeCRHGriffin, IntervalCRH, UTXOCRH,
                utils::{
                    initialize_blockcrh_config_griffin, initialize_griffin_config,
                    initialize_n_to_one_config, initialize_n_to_one_config_griffin,
                    initialize_poseidon_config, initialize_two_to_one_binary_tree_poseidon_config,
                },
            },
            sparsemt::MerkleSparseTree,
        },
    };

    #[test]
    fn test_validity_circuit() {
        let mut rng = test_rng();

        // initialize our plasma blind config
        // poseidon crh only for now, should be configurable in the future
        let two_to_one_poseidon_config = initialize_two_to_one_binary_tree_poseidon_config::<Fr>();
        let poseidon_config = initialize_poseidon_config::<Fr>();
        let griffin_config = initialize_griffin_config::<Fr>();

        let utxo_crh_config = UTXOCRH::setup(&mut rng).unwrap();
        let shielded_tx_leaf_config = ();
        let tx_tree_leaf_config = ();
        let signer_tree_leaf_config = ();
        let nullifier_tree_leaf_config = IntervalCRH::setup(&mut rng).unwrap();
        let block_tree_leaf_config = BlockTreeCRHGriffin::setup(&mut rng).unwrap();

        let shielded_tx_two_to_one_config = two_to_one_poseidon_config.clone();
        let nullifier_tree_two_to_one_config = two_to_one_poseidon_config.clone();
        let block_tree_n_to_one_config =
            initialize_n_to_one_config_griffin::<BLOCK_TREE_ARITY, Fr>();
        let tx_tree_n_to_one_config =
            initialize_n_to_one_config_griffin::<TRANSACTION_TREE_ARITY, Fr>();
        let signer_tree_n_to_one_config =
            initialize_n_to_one_config_griffin::<SIGNER_TREE_ARITY, Fr>();

        let config = PlasmaBlindConfig::new(
            poseidon_config.clone(),
            griffin_config.clone(),
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
        let alice_pk = CRH::evaluate(&config.poseidon_config, vec![alice_sk]).unwrap();
        let bob_sk = Fr::rand(&mut rng);
        let bob_pk = CRH::evaluate(&config.poseidon_config, vec![bob_sk]).unwrap();

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
            &config.griffin_config,
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

        assert!(
            block_inclusion_proof
                .verify(
                    &block_tree.leaf_hash_param,
                    &block_tree_n_to_one_config.clone(),
                    &block_tree.root(),
                    prev_block.clone(),
                )
                .unwrap()
        );

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
            &config.griffin_config,
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
        tx_validity_circuit
            .clone()
            .generate_constraints(cs_ref.clone())
            .unwrap();
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
        let (len_wtns, size) = (rw.w.len(), rw.w.serialized_size(Compress::Yes));
        println!("len wtns: {len_wtns}, compressed_size: {size}");
    }
}

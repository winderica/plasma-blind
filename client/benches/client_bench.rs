use std::{collections::BTreeMap, sync::Arc, time::Duration};

use ark_bn254::{Fr, G1Projective, G1Projective as C1};
use ark_crypto_primitives::{crh::CRHScheme, sponge::poseidon::PoseidonConfig};
use ark_ff::UniformRand;
use ark_grumpkin::Projective as C2;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::test_rng;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use plasmablind_core::{
    config::PlasmaBlindConfig,
    datastructures::{
        TX_IO_SIZE,
        block::BlockMetadata,
        blocktree::{BLOCK_TREE_ARITY, SparseNAryBlockTree},
        shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
        signerlist::{SIGNER_TREE_ARITY, SparseNArySignerTree},
        transparenttx::TransparentTransaction,
        txtree::{TRANSACTION_TREE_ARITY, SparseNAryTransactionTree},
        utxo::{UTXO, UTXOInfo, proof::UTXOProof},
    },
    primitives::{
        crh::{BlockTreeCRH, IntervalCRH, UTXOCRH, utils::Init},
        sparsemt::MerkleSparseTree,
    },
};
use sonobe_fs::{
    DeciderKey, FoldingSchemeDef, FoldingSchemeKeyGenerator, FoldingSchemePreprocessor,
    FoldingSchemeProver,
    nova::{
        Nova,
        instances::{IncomingInstance, RunningInstance},
        witnesses::{IncomingWitness, RunningWitness},
    },
    ova::CycleFoldOva,
};
use sonobe_ivc::{IVC, IVCStatefulProver, compilers::cyclefold::CycleFoldBasedIVC};
use sonobe_primitives::{
    circuits::{Assignments, ConstraintSystemBuilder},
    commitments::pedersen::Pedersen,
    relations::WitnessInstanceSampler,
    transcripts::{
        Transcript,
        griffin::{GriffinParams, sponge::GriffinSponge},
    },
};

use client::{
    balance::{
        balance_inputs::BalanceAux,
        balance_state::BalanceState,
        circuit::BalanceCircuit,
    },
    transaction::TransactionValidityCircuit,
};

// ---------------------------------------------------------------------------
// Helpers: build a PlasmaBlindConfig and a TransactionValidityCircuit
// ---------------------------------------------------------------------------

fn build_config<Cfg: Init<F = Fr>>() -> PlasmaBlindConfig<Cfg> {
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

    PlasmaBlindConfig::new(
        hash_config,
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
    )
}

/// Builds a full `TransactionValidityCircuit` with realistic inputs (bob-to-alice scenario).
fn build_validity_circuit<Cfg: Init<F = Fr>>(
    config: &PlasmaBlindConfig<Cfg>,
) -> TransactionValidityCircuit<Cfg> {
    let mut rng = test_rng();

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

    TransactionValidityCircuit::new(
        bob_sk,
        bob_pk,
        bob_to_alice_tx,
        bob_to_alice_shielded_tx,
        block_tree.root(),
        bob_input_utxos_proofs,
        config.clone(),
    )
}

// ---------------------------------------------------------------------------
// A. TransactionValidityCircuit — End-to-End Prove (synthesis + Nova fold)
// ---------------------------------------------------------------------------

fn bench_validity_prove<Cfg: Init<F = Fr>>(c: &mut Criterion, name: &str) {
    let config = build_config::<Cfg>();
    let circuit = build_validity_circuit(&config);
    let mut rng = test_rng();

    // Pre-compute decider keys (expensive, one-time setup)
    let cs = ConstraintSystemBuilder::new()
        .with_prove_mode()
        .with_circuit(circuit.clone())
        .synthesize()
        .unwrap();
    let ck_size = cs.num_constraints().max(cs.num_witness_variables());

    let arith = <Nova<Pedersen<G1Projective, true>> as FoldingSchemeDef>::Arith::from(cs);
    let pp_f = Nova::<Pedersen<G1Projective, true>>::preprocess(ck_size, &mut rng).unwrap();
    let dk = Nova::<Pedersen<G1Projective, true>>::generate_keys(pp_f, arith).unwrap();

    let hash_config = Arc::new(GriffinParams::new(16, 5, 9));

    c.bench_function(
        &format!("client/validity_circuit/prove/{name}"),
        |b| {
            b.iter_batched(
                || {
                    let mut rng = test_rng();
                    let (W, U): (
                        RunningWitness<Pedersen<G1Projective, true>>,
                        RunningInstance<Pedersen<G1Projective, true>>,
                    ) = dk.sample((), &mut rng).unwrap();
                    (circuit.clone(), W, U, rng)
                },
                |(circ, W, U, mut rng)| {
                    // Synthesis
                    let cs_ref = ConstraintSystem::new_ref();
                    circ.generate_constraints(cs_ref.clone()).unwrap();
                    let (w, x) = (
                        cs_ref.witness_assignment().unwrap(),
                        cs_ref
                            .instance_assignment()
                            .unwrap()
                            .into_iter()
                            .skip(1)
                            .collect(),
                    );
                    let assignments = Assignments::from((Fr::from(1), x, w));
                    let (w, u): (
                        IncomingWitness<Pedersen<G1Projective, true>>,
                        IncomingInstance<Pedersen<G1Projective, true>>,
                    ) = dk.sample(assignments, &mut rng).unwrap();

                    // Nova fold
                    let hash =
                        GriffinSponge::<Fr>::new_with_pp_hash(&hash_config, Default::default());
                    let mut transcript = hash.separate_domain("transcript1".as_ref());
                    Nova::<Pedersen<G1Projective, true>>::prove(
                        dk.to_pk(),
                        &mut transcript,
                        &[W],
                        &[U],
                        &[w],
                        &[u],
                        &mut rng,
                    )
                    .unwrap();
                },
                BatchSize::LargeInput,
            )
        },
    );
}

// ---------------------------------------------------------------------------
// C. BalanceCircuit — IVC Prove Step
// ---------------------------------------------------------------------------

fn bench_balance_prove_step<Cfg: Init<F = Fr>>(c: &mut Criterion, name: &str) {
    type FS1 = Nova<Pedersen<C1, true>>;
    type FS2 = CycleFoldOva<Pedersen<C2, true>>;
    type T = GriffinSponge<Fr>;

    let mut rng = test_rng();

    let config = build_config::<Cfg>();
    let sender_sk = Fr::rand(&mut rng);
    let sender_pk = Cfg::H::evaluate(&config.hash_config, vec![sender_sk]).unwrap();
    let receiver_sk = Fr::rand(&mut rng);
    let receiver_pk = Cfg::H::evaluate(&config.hash_config, vec![receiver_sk]).unwrap();

    let mut outputs = [Default::default(); TX_IO_SIZE];
    for i in 0..TX_IO_SIZE - 1 {
        outputs[i] = UTXO::new(sender_pk, 10, Fr::rand(&mut rng));
    }
    outputs[TX_IO_SIZE - 1] = UTXO::new(receiver_pk, 10, Fr::rand(&mut rng));
    let tx = TransparentTransaction {
        inputs: [UTXO::new(sender_pk, 10, Fr::rand(&mut rng)); TX_IO_SIZE],
        inputs_info: [Default::default(); TX_IO_SIZE],
        outputs,
    };
    let shielded_tx =
        ShieldedTransaction::new(&config.hash_config, &config.utxo_crh_config, &sender_sk, &tx)
            .unwrap();
    let utxo_tree = MerkleSparseTree::<ShieldedTransactionConfig<_>>::new(
        &config.shielded_tx_leaf_config,
        &config.shielded_tx_two_to_one_config,
        &BTreeMap::from_iter(shielded_tx.output_utxo_commitments.into_iter().enumerate()),
    )
    .unwrap();

    let signer_tree = SparseNArySignerTree::new(
        &config.signer_tree_leaf_config,
        &config.signer_tree_n_to_one_config,
        &BTreeMap::from([(1, sender_pk)]),
        &Fr::default(),
    )
    .unwrap();
    let transaction_tree = SparseNAryTransactionTree::new(
        &(),
        &config.tx_tree_n_to_one_config,
        &BTreeMap::from([(1, utxo_tree.root())]),
        &Fr::default(),
    )
    .unwrap();

    let block = BlockMetadata {
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        nullifier_tree_root: Fr::default(),
        height: 1,
    };
    let shielded_tx_utxos_proofs = (0..TX_IO_SIZE)
        .map(|idx| {
            (
                utxo_tree.generate_membership_proof(idx).unwrap(),
                Fr::from(idx as u64),
            )
        })
        .collect::<Vec<_>>();
    let shielded_tx_inclusion_proof = transaction_tree.generate_proof(1).unwrap();
    let signer_inclusion_proof = signer_tree.generate_proof(1).unwrap();
    let sender_aux = BalanceAux::<Cfg> {
        block,
        from: sender_pk,
        utxo_tree_root: utxo_tree.root(),
        shielded_tx_utxos: tx.outputs.to_vec(),
        shielded_tx_utxos_proofs,
        openings_mask: vec![true; TX_IO_SIZE],
        shielded_tx_inclusion_proof,
        signer_pk_inclusion_proof: signer_inclusion_proof,
    };

    let z_i = BalanceState {
        balance: 10000000,
        nonce: Fr::from(11),
        pk: sender_pk,
        acc: Fr::from(13),
        block_hash: Fr::from(42),
        block_number: 0,
        processed_tx_index: 0,
    };

    let circuit = BalanceCircuit { config };

    let mut rng1 = test_rng();
    let hash_config = Arc::new(GriffinParams::new(16, 5, 9));
    let pp = CycleFoldBasedIVC::<FS1, FS2, T>::preprocess(
        (1 << 19, (2048, 2048), hash_config.clone()),
        &mut rng1,
    )
    .unwrap();
    let (pk, _vk) = CycleFoldBasedIVC::<FS1, FS2, T>::generate_keys(pp, &circuit).unwrap();

    let num_steps = 3;

    c.bench_function(
        &format!("client/balance_circuit/prove_step/{name}"),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut prover =
                        IVCStatefulProver::<_, CycleFoldBasedIVC<FS1, FS2, T>>::new(
                            &pk, &circuit, z_i.clone(),
                        )
                        .unwrap();
                    let mut aux = sender_aux.clone();
                    let start = std::time::Instant::now();
                    for _ in 0..num_steps {
                        prover.prove_step(aux.clone(), &mut rng).unwrap();
                        aux.block.height += 1;
                    }
                    total += start.elapsed();
                }
                // Report per-step average
                total / num_steps as u32
            });
        },
    );
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

fn bench_prove_poseidon(c: &mut Criterion) {
    bench_validity_prove::<PoseidonConfig<Fr>>(c, "poseidon");
}

fn bench_prove_griffin(c: &mut Criterion) {
    bench_validity_prove::<GriffinParams<Fr>>(c, "griffin");
}

fn bench_balance_poseidon(c: &mut Criterion) {
    bench_balance_prove_step::<PoseidonConfig<Fr>>(c, "poseidon");
}

fn bench_balance_griffin(c: &mut Criterion) {
    bench_balance_prove_step::<GriffinParams<Fr>>(c, "griffin");
}

criterion_group! {
    name = validity_proving;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(5));
    targets = bench_prove_poseidon, bench_prove_griffin
}

criterion_group! {
    name = balance_proving;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
        .warm_up_time(Duration::from_secs(5));
    targets = bench_balance_poseidon, bench_balance_griffin
}

criterion_main!(validity_proving, balance_proving);

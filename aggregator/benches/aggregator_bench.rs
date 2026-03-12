use std::{collections::{BTreeMap, HashMap}, marker::PhantomData, sync::Arc, time::Duration};

use ark_bn254::{Fr, G1Projective as C1};
use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::UniformRand;
use ark_grumpkin::Projective as C2;
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_std::{
    rand::{Rng, thread_rng},
    test_rng,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use plasmablind_core::{
    config::PlasmaBlindConfig,
    datastructures::{
        TX_IO_SIZE,
        block::BlockMetadata,
        blocktree::{BLOCK_TREE_ARITY, SparseNAryBlockTree},
        shieldedtx::{ShieldedTransaction, UTXOTree},
        signerlist::{SIGNER_TREE_ARITY, SparseNArySignerTree},
        transparenttx::TransparentTransaction,
        txtree::{TRANSACTION_TREE_ARITY, SparseNAryTransactionTree},
        utxo::{UTXO, UTXOInfo, proof::UTXOProof},
    },
    primitives::crh::{BlockTreeCRH, IntervalCRH, UTXOCRH, utils::Init},
};
use sonobe_fs::{
    DeciderKey,
    FoldingSchemeKeyGenerator, FoldingSchemePreprocessor,
    FoldingSchemeProver,
    nova::Nova,
    ova::CycleFoldOva,
};
use sonobe_ivc::{
    IVC,
    compilers::cyclefold::{CycleFoldBasedIVC, FoldingSchemeCycleFoldExt, circuits::CycleFoldCircuit},
};
use sonobe_primitives::{
    arithmetizations::r1cs::R1CS,
    circuits::{ConstraintSystemBuilder, ConstraintSystemExt},
    commitments::pedersen::Pedersen,
    relations::WitnessInstanceSampler,
    transcripts::{
        Transcript,
        griffin::{GriffinParams, sponge::GriffinSponge},
    },
};

use aggregator::{
    Aggregator,
    circuits::AggregatorCircuit,
};
use client::transaction::TransactionValidityCircuit;

type FS1 = Nova<Pedersen<C1, true>>;
type FS2 = CycleFoldOva<Pedersen<C2, true>>;
type T = GriffinSponge<Fr>;

// ---------------------------------------------------------------------------
// Setup helpers
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

/// Full aggregator test harness — sets up users, transactions, proofs, and the aggregator.
/// Returns everything needed for benchmarking individual phases.
struct AggregatorHarness {
    aggregator: Aggregator<FS1, FS2, T, PoseidonConfig<Fr>>,
    senders: Vec<Fr>,
    transactions: Vec<ShieldedTransaction<Fr>>,
    proofs: Vec<Option<(<FS1 as sonobe_fs::FoldingSchemeDef>::RW, <FS1 as sonobe_fs::FoldingSchemeDef>::RU, <FS1 as sonobe_fs::FoldingSchemeDef>::IU, <FS1 as sonobe_fs::FoldingSchemeDef>::Proof<1, 1>)>>,
    block_root: Fr,
}

fn build_harness(n_target_txs: usize) -> AggregatorHarness {
    let config = build_config::<PoseidonConfig<Fr>>();

    let mut rng = thread_rng();
    let mut rng1 = test_rng();

    let user_circuit = TransactionValidityCircuit::new(
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        vec![Default::default(); TX_IO_SIZE],
        config.clone(),
    );

    let hash_config = Arc::new(GriffinParams::new(16, 5, 9));

    let pp = CycleFoldBasedIVC::<FS1, FS2, T>::preprocess(
        (1 << 19, (2048, 2048), hash_config.clone()),
        &mut rng1,
    )
    .unwrap();

    let pp_f = FS1::preprocess(1 << 16, &mut rng1).unwrap();

    let cyclefold_circuit =
        CycleFoldCircuit::<<FS1 as FoldingSchemeCycleFoldExt<1, 1>>::CFConfig>::default();

    let cs = ConstraintSystemBuilder::new()
        .with_setup_mode()
        .with_circuit(cyclefold_circuit)
        .synthesize()
        .unwrap();
    let arith2 = R1CS::from(cs);
    let dk2 = FS2::generate_keys(pp.1.clone(), arith2).unwrap();

    let cs = ConstraintSystemBuilder::new()
        .with_setup_mode()
        .with_circuit(user_circuit)
        .synthesize()
        .unwrap();
    let arith1 = R1CS::from(cs);
    let dk1 = FS1::generate_keys(pp_f, arith1).unwrap();

    let circuit = AggregatorCircuit {
        config: config.clone(),
        hash_config: hash_config.clone(),
        pp_hash: Default::default(),
        dk1: dk1.clone(),
        dk2: dk2.clone(),
        _r: PhantomData,
    };
    let (pk, _vk) = CycleFoldBasedIVC::<FS1, FS2, T>::generate_keys(pp, &circuit).unwrap();
    let mut aggregator = Aggregator::<FS1, FS2, T, PoseidonConfig<Fr>>::new(circuit, pk);

    // Set up users — use enough users to generate at least n_target_txs
    let n_users = n_target_txs * 4; // oversubscribe to get enough txs
    let user_sks = (0..n_users).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let user_pks = user_sks
        .iter()
        .map(|&sk| CRH::<Fr>::evaluate(&config.hash_config, vec![sk]))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut user_utxos = user_pks
        .iter()
        .map(|pk| (*pk, HashMap::new()))
        .collect::<BTreeMap<_, _>>();

    // Block 0 — generate transactions to give users UTXOs
    let mut block_tree = SparseNAryBlockTree::blank(
        &config.block_tree_leaf_config,
        &config.block_tree_n_to_one_config,
        &BlockMetadata::default(),
    )
    .unwrap();

    let block_height = 0;
    let mut transactions_map = BTreeMap::new();
    let mut signers_map = BTreeMap::new();

    for sender_index in 0..n_users {
        let mut tx = TransparentTransaction::default();
        for utxo_index in 0..TX_IO_SIZE {
            let receiver_index = rng.gen_range(0..n_users);
            let amount: u32 = rng.r#gen();
            let utxo = UTXO::new(user_pks[receiver_index], amount as u64, Fr::rand(&mut rng));
            tx.set_output(utxo_index, utxo);
        }

        let shielded_tx = ShieldedTransaction::new(
            &config.hash_config,
            &config.utxo_crh_config,
            &user_sks[sender_index],
            &tx,
        )
        .unwrap();

        let utxo_tree = UTXOTree::new(
            &config.shielded_tx_leaf_config,
            &config.shielded_tx_two_to_one_config,
            &BTreeMap::from_iter(
                shielded_tx.output_utxo_commitments.into_iter().enumerate(),
            ),
        )
        .unwrap();

        for utxo_index in 0..TX_IO_SIZE {
            let utxo = tx.outputs[utxo_index];
            if !utxo.is_dummy {
                let utxo_info = UTXOInfo {
                    utxo_index,
                    tx_index: transactions_map.len(),
                    block_height,
                    from: user_pks[sender_index],
                };
                let utxo_inclusion_proof =
                    utxo_tree.generate_membership_proof(utxo_index).unwrap();
                user_utxos
                    .get_mut(&utxo.pk)
                    .unwrap()
                    .insert(utxo, (utxo_info, utxo_inclusion_proof));
            }
        }

        transactions_map.insert(transactions_map.len(), utxo_tree.root());
        signers_map.insert(signers_map.len(), user_pks[sender_index]);
    }

    let transactions_tree = SparseNAryTransactionTree::new(
        &config.tx_tree_leaf_config,
        &config.tx_tree_n_to_one_config,
        &transactions_map,
        &Fr::default(),
    )
    .unwrap();

    let signer_tree = SparseNArySignerTree::new(
        &config.signer_tree_leaf_config,
        &config.signer_tree_n_to_one_config,
        &signers_map,
        &Fr::default(),
    )
    .unwrap();

    let prev_block = BlockMetadata {
        tx_tree_root: transactions_tree.root(),
        signer_tree_root: signer_tree.root(),
        nullifier_tree_root: Fr::default(),
        height: block_height,
    };
    block_tree.update(block_height, &prev_block).unwrap();
    let block_inclusion_proof = block_tree.generate_proof(block_height).unwrap();

    let transaction_inclusion_proofs = (0..transactions_map.len())
        .map(|i| transactions_tree.generate_proof(i))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let signer_inclusion_proofs = (0..signers_map.len())
        .map(|i| signer_tree.generate_proof(i))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Block 1 — build actual transactions to benchmark
    let mut out_transactions = vec![];
    let mut out_senders = vec![];
    let mut assignments_vec = vec![];

    for sender_index in 0..n_users {
        if out_transactions.len() >= n_target_txs {
            break;
        }

        let owned_utxos = user_utxos[&user_pks[sender_index]]
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        if !owned_utxos.is_empty() {
            let mut tx = TransparentTransaction::default();
            let mut input_utxos_proofs = vec![UTXOProof::default(); TX_IO_SIZE];

            for utxo_index in 0..TX_IO_SIZE.min(owned_utxos.len()) {
                let utxo = owned_utxos[utxo_index];
                let (info, proof) = user_utxos
                    .get_mut(&user_pks[sender_index])
                    .unwrap()
                    .remove(&utxo)
                    .unwrap();
                tx.set_input(utxo_index, utxo, info);
                input_utxos_proofs[utxo_index] = UTXOProof::new(
                    prev_block.clone(),
                    proof,
                    signer_inclusion_proofs[info.tx_index].clone(),
                    transaction_inclusion_proofs[info.tx_index].clone(),
                    block_inclusion_proof.clone(),
                );
            }

            let amount = tx.inputs.iter().map(|i| i.amount).sum::<u64>();
            let amount1 = rng.gen_range(0..=amount);
            let amount2 = amount - amount1;
            let receiver_index1 = rng.gen_range(0..n_users);
            let receiver_index2 = rng.gen_range(0..n_users);

            tx.set_output(
                0,
                UTXO::new(user_pks[receiver_index1], amount1, Fr::rand(&mut rng)),
            );
            tx.set_output(
                1,
                UTXO::new(user_pks[receiver_index2], amount2, Fr::rand(&mut rng)),
            );

            let shielded_tx = ShieldedTransaction::new(
                &config.hash_config,
                &config.utxo_crh_config,
                &user_sks[sender_index],
                &tx,
            )
            .unwrap();

            let cs = ark_relations::gr1cs::ConstraintSystem::new_ref();
            TransactionValidityCircuit::new(
                user_sks[sender_index],
                user_pks[sender_index],
                tx,
                shielded_tx.clone(),
                block_tree.root(),
                input_utxos_proofs,
                config.clone(),
            )
            .generate_constraints(cs.clone())
            .unwrap();
            assert!(cs.is_satisfied().unwrap());

            assignments_vec.push(cs.assignments().unwrap());
            out_senders.push(user_pks[sender_index]);
            out_transactions.push(shielded_tx);
        }
    }

    // Process transactions and generate validity proofs
    aggregator.process_transactions(out_senders.clone(), out_transactions.clone());

    let mut proofs = vec![];
    for assignments in assignments_vec {
        let hash = T::new_with_pp_hash(&hash_config, Default::default());
        let mut transcript1 = hash.separate_domain("transcript1".as_ref());

        let (W, U) = dk1.sample((), &mut rng1).unwrap();
        let (w, u) = dk1.sample(assignments, &mut rng1).unwrap();
        let (WW, _, proof, _) = FS1::prove(
            dk1.to_pk(),
            &mut transcript1,
            &[&W],
            &[&U],
            &[&w],
            &[&u],
            &mut rng1,
        )
        .unwrap();
        proofs.push(Some((WW, U, u, proof)));
    }

    AggregatorHarness {
        aggregator,
        senders: out_senders,
        transactions: out_transactions,
        proofs,
        block_root: block_tree.root(),
    }
}

// ---------------------------------------------------------------------------
// A. Process Transactions
// ---------------------------------------------------------------------------

fn bench_process_transactions(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregator/process_transactions");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for n in [2, 4, 8, 16, 32, 64, 128] {
        let mut harness = build_harness(n);
        let actual_n = harness.transactions.len();

        group.bench_with_input(BenchmarkId::new("n", actual_n), &actual_n, |b, _| {
            b.iter(|| {
                harness.aggregator.process_transactions(
                    harness.senders.clone(),
                    harness.transactions.clone(),
                );
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// B. Validity Proof Preparation (verification of per-tx Nova proofs)
// ---------------------------------------------------------------------------

fn bench_validity_proof_preparation(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregator/validity_proof_preparation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    group.warm_up_time(Duration::from_secs(5));

    for n in [2, 4, 8, 16, 32, 64, 128] {
        let harness = build_harness(n);
        let actual_n = harness.proofs.len();

        group.bench_with_input(BenchmarkId::new("n", actual_n), &actual_n, |b, _| {
            // prepare_validity_proofs takes &self (no mutation), so we can reuse the harness
            b.iter(|| {
                harness.aggregator.prepare_validity_proofs(
                    harness.proofs.clone(),
                    harness.block_root,
                )
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// C. IVC Proof Aggregation (core aggregation via CycleFoldBasedIVC)
// ---------------------------------------------------------------------------

fn bench_ivc_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregator/ivc_aggregation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(5));

    for n in [2, 4, 8, 16, 32, 64, 128] {
        let actual_n = {
            let h = build_harness(n);
            h.proofs.len()
        };

        group.bench_with_input(BenchmarkId::new("n", actual_n), &actual_n, |b, &n_val| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut harness = build_harness(n_val);
                    // Pre-compute validated proofs outside the timed section
                    let (valid_indexes, valid_proofs) = harness.aggregator.prepare_validity_proofs(
                        harness.proofs.clone(),
                        harness.block_root,
                    );
                    // Benchmark only the IVC aggregation phase
                    let start = std::time::Instant::now();
                    harness.aggregator.aggregate_validity_proofs(
                        valid_indexes,
                        valid_proofs,
                        harness.block_root,
                    );
                    total += start.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

criterion_group! {
    name = process_txs;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10));
    targets = bench_process_transactions
}

criterion_group! {
    name = aggregation;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
        .warm_up_time(Duration::from_secs(5));
    targets = bench_validity_proof_preparation, bench_ivc_aggregation
}

criterion_main!(process_txs, aggregation);

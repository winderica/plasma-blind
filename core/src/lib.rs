pub mod circuit;
pub mod config;
pub mod datastructures;
pub mod errs;
pub mod primitives;
pub mod utils;

const TX_TREE_HEIGHT: u64 = 13;
const SIGNER_TREE_HEIGHT: u64 = TX_TREE_HEIGHT;

#[cfg(test)]
pub mod tests {

    use ark_bn254::G1Projective;
    use ark_ff::PrimeField;
    use ark_relations::gr1cs::ConstraintSynthesizer;
    use sonobe_fs::{
        DeciderKey, FoldingSchemeDef, FoldingSchemeOps,
        nova::{
            Nova,
            instance::{IncomingInstance, RunningInstance},
            witness::{IncomingWitness, RunningWitness},
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
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use ark_crypto_primitives::{
        crh::{
            CRHScheme, TwoToOneCRHScheme,
            poseidon::{CRH, TwoToOneCRH},
        },
        merkle_tree::Path,
        sponge::Absorb,
    };

    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_grumpkin::constraints::GVar as GrumpkinProjectiveVar;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;

    use crate::circuit::TransactionValidityCircuit;
    use crate::primitives::crh::utils::initialize_two_to_one_binary_tree_poseidon_config;
    use crate::{
        config::PlasmaBlindConfig,
        datastructures::utxo::proof::UTXOProof,
        datastructures::{
            TX_IO_SIZE,
            block::Block,
            nullifier::Nullifier,
            shieldedtx::ShieldedTransaction,
            signerlist::{SignerTreeConfig, constraints::SignerTreeConfigGadget},
            transparenttx::TransparentTransaction,
            txtree::{TransactionTreeConfig, constraints::TransactionTreeConfigGadget},
            user::User,
        },
        primitives::{
            crh::{
                BlockCRH, BlockTreeCRH, PublicKeyCRH, ShieldedTransactionCRH, UTXOCRH,
                utils::initialize_poseidon_config,
            },
            sparsemt::{MerkleSparseTree, SparseConfig},
        },
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

        let tx_validity_circuit = TransactionValidityCircuit::<
            _,
            GrumpkinProjectiveVar,
            _,
            TransactionTreeConfigGadget<_, GrumpkinProjectiveVar>,
            _,
            SignerTreeConfigGadget<_, GrumpkinProjectiveVar>,
        >::new(
            bob_sk,
            bob_pk,
            bob.keypair.pk,
            bob_to_alice_tx.clone(),
            bob_to_alice_shielded_tx,
            bob_to_alice_tx.outputs.to_vec(),
            bob_to_alice_shielded_tx_output_proofs,
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
            .with_setup_mode()
            .with_circuit(tx_validity_circuit)
            .synthesize()
            .unwrap();
        let ck_size = cs.num_constraints().max(cs.num_witness_variables());

        let assignments = Assignments::from((Fr::from(1), x, w));
        let arith = <Nova<Pedersen<G1Projective, true>> as FoldingSchemeDef>::Arith::from(cs);
        let pp_f = <Nova<Pedersen<G1Projective, true>> as FoldingSchemeOps<1, 1>>::preprocess(
            ck_size, &mut rng,
        )
        .unwrap();
        let dk = <Nova<Pedersen<G1Projective, true>> as FoldingSchemeOps<1, 1>>::generate_keys(
            pp_f, arith,
        )
        .unwrap();
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

        let res = <Nova<Pedersen<G1Projective, true>> as FoldingSchemeOps<1, 1>>::prove(
            dk.to_pk(),
            &mut transcript,
            &[W],
            &[U],
            &[w],
            &[u],
            &mut rng,
        )
        .unwrap();
    }
}

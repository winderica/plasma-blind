use std::collections::BTreeMap;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{One, PrimeField, Zero};
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::ops::Bound::{Excluded, Unbounded};
use ark_std::rand::rngs::ThreadRng;
use ark_std::rand::thread_rng;
use ark_std::test_rng;
use nmerkle_trees::sparse::NArySparsePath;
use plasmablind_core::datastructures::shieldedtx::{ShieldedTransaction, UTXOTree};
use plasmablind_core::datastructures::signerlist::SparseNArySignerTree;
use plasmablind_core::datastructures::txtree::{
    SparseNAryTransactionTree, SparseNAryTransactionTreeConfig, TRANSACTION_TREE_ARITY,
    TransactionTreeConfig,
};
use plasmablind_core::datastructures::{
    nullifier::NullifierTree, signerlist::SignerTree, txtree::TransactionTree,
};
use sonobe_fs::{
    DeciderKey, FoldingInstance, FoldingSchemeGadgetOpsFull, FoldingSchemeGadgetOpsPartial,
    GroupBasedFoldingSchemeSecondary,
};
use sonobe_ivc::compilers::cyclefold::{CycleFoldBasedIVC, FoldingSchemeCycleFoldExt};
use sonobe_ivc::{IVC, IVCStatefulProver};
use sonobe_primitives::commitments::VectorCommitmentDef;
use sonobe_primitives::traits::Dummy;
use sonobe_primitives::traits::{CF1, SonobeCurve};
use sonobe_primitives::transcripts::Transcript;

use crate::circuits::{AggregatorCircuit, AggregatorCircuitExternalInputs, AggregatorCircuitState};

pub mod circuits;

pub struct Aggregator<
    FS1: FoldingSchemeCycleFoldExt<
            2,
            0,
            Gadget: FoldingSchemeGadgetOpsPartial<2, 0, VerifierKey = ()>,
            VC: VectorCommitmentDef<
                Commitment: SonobeCurve<
                    BaseField = <FS2::VC as VectorCommitmentDef>::Scalar,
                    ScalarField: Absorb,
                >,
            >,
        > + FoldingSchemeCycleFoldExt<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeGadgetOpsPartial<1, 1, VerifierKey = ()>,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS2::VC as VectorCommitmentDef>::Commitment>>>,
            PublicParam: Clone,
            Gadget: FoldingSchemeGadgetOpsFull<1, 1, VerifierKey = ()>,
            VC: VectorCommitmentDef<
                Commitment: SonobeCurve<
                    BaseField = <FS1::VC as VectorCommitmentDef>::Scalar,
                    ScalarField: Absorb,
                >,
            >,
        >,
    T: Transcript<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>,
> {
    pk: <CycleFoldBasedIVC<FS1, FS2, T> as IVC>::ProverKey<
        AggregatorCircuit<T, FS1, FS2, ThreadRng>,
    >,
    circuit: AggregatorCircuit<T, FS1, FS2, ThreadRng>,

    transactions: Vec<ShieldedTransaction<FS1::TranscriptField>>,
    transaction_tree: SparseNAryTransactionTree<FS1::TranscriptField>,
    transaction_validity_proofs: Vec<(FS1::RW, FS1::RU, FS1::IU, FS1::Proof<1, 1>)>,

    senders: Vec<FS1::TranscriptField>,
    signer_tree: SparseNArySignerTree<FS1::TranscriptField>,

    nullifiers: BTreeMap<FS1::TranscriptField, (usize, usize)>,
    nullifier_tree: NullifierTree<FS1::TranscriptField>,
}

impl<
    FS1: FoldingSchemeCycleFoldExt<
            2,
            0,
            Gadget: FoldingSchemeGadgetOpsPartial<2, 0, VerifierKey = ()>,
            VC: VectorCommitmentDef<
                Commitment: SonobeCurve<
                    BaseField = <FS2::VC as VectorCommitmentDef>::Scalar,
                    ScalarField: Absorb,
                >,
            >,
        > + FoldingSchemeCycleFoldExt<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeGadgetOpsPartial<1, 1, VerifierKey = ()>,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS2::VC as VectorCommitmentDef>::Commitment>>>,
            PublicParam: Clone,
            Gadget: FoldingSchemeGadgetOpsFull<1, 1, VerifierKey = ()>,
            VC: VectorCommitmentDef<
                Commitment: SonobeCurve<
                    BaseField = <FS1::VC as VectorCommitmentDef>::Scalar,
                    ScalarField: Absorb,
                >,
            >,
        >,
    T: Transcript<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>,
> Aggregator<FS1, FS2, T>
{
    fn new(
        circuit: AggregatorCircuit<T, FS1, FS2, ThreadRng>,
        pk: <CycleFoldBasedIVC<FS1, FS2, T> as IVC>::ProverKey<
            AggregatorCircuit<T, FS1, FS2, ThreadRng>,
        >,
    ) -> Self {
        let transaction_tree = SparseNAryTransactionTree::blank(
            &circuit.config.tx_tree_leaf_config,
            &circuit.config.tx_tree_n_to_one_config,
            &FS1::TranscriptField::default(),
        )
        .unwrap();
        let signer_tree = SparseNArySignerTree::blank(
            &circuit.config.signer_tree_leaf_config,
            &circuit.config.signer_tree_n_to_one_config,
            &FS1::TranscriptField::default(),
        )
        .unwrap();
        let mut nullifier_tree = NullifierTree::blank(
            &circuit.config.nullifier_tree_leaf_config,
            &circuit.config.nullifier_tree_two_to_one_config,
        );
        nullifier_tree
            .update_and_prove(
                0,
                &(FS1::TranscriptField::zero(), FS1::TranscriptField::zero()),
            )
            .unwrap();
        nullifier_tree
            .update_and_prove(
                1,
                &(
                    FS1::TranscriptField::zero(),
                    FS1::TranscriptField::from(FS1::TranscriptField::MODULUS_MINUS_ONE_DIV_TWO),
                ),
            )
            .unwrap();
        nullifier_tree
            .update_and_prove(
                2,
                &(
                    FS1::TranscriptField::from(FS1::TranscriptField::MODULUS_MINUS_ONE_DIV_TWO),
                    FS1::TranscriptField::from(FS1::TranscriptField::MODULUS_MINUS_ONE_DIV_TWO),
                ),
            )
            .unwrap();
        let nullifiers = BTreeMap::from([
            (FS1::TranscriptField::zero(), (0, 1)),
            (
                FS1::TranscriptField::from(FS1::TranscriptField::MODULUS_MINUS_ONE_DIV_TWO),
                (1, 2),
            ),
        ]);

        Self {
            pk,
            circuit,
            transactions: vec![],
            transaction_tree,
            transaction_validity_proofs: vec![],
            senders: vec![],
            signer_tree,
            nullifiers,
            nullifier_tree,
        }
    }

    pub fn reset_for_new_epoch(&mut self) {
        self.transactions.clear();
        self.transaction_validity_proofs.clear();
        self.transaction_tree = SparseNAryTransactionTree::blank(
            &self.circuit.config.tx_tree_leaf_config,
            &self.circuit.config.tx_tree_n_to_one_config,
            &FS1::TranscriptField::default(),
        )
        .unwrap();
        self.senders.clear();
        self.signer_tree = SparseNArySignerTree::blank(
            &self.circuit.config.signer_tree_leaf_config,
            &self.circuit.config.signer_tree_n_to_one_config,
            &FS1::TranscriptField::default(),
        )
        .unwrap();
    }

    pub fn process_transactions(
        &mut self,
        senders: Vec<FS1::TranscriptField>,
        txs: Vec<ShieldedTransaction<FS1::TranscriptField>>,
    ) {
        self.transactions = txs;
        self.senders = senders;
        self.transaction_tree = SparseNAryTransactionTree::new(
            &self.circuit.config.tx_tree_leaf_config,
            &self.circuit.config.tx_tree_n_to_one_config,
            &BTreeMap::from_iter(
                self.transactions
                    .iter()
                    .map(|tx| {
                        UTXOTree::new(
                            &self.circuit.config.shielded_tx_leaf_config,
                            &self.circuit.config.shielded_tx_two_to_one_config,
                            &BTreeMap::from_iter(
                                tx.output_utxo_commitments.iter().cloned().enumerate(),
                            ),
                        )
                        .unwrap()
                        .root()
                    })
                    .enumerate(),
            ),
            &FS1::TranscriptField::default(),
        )
        .unwrap();
    }

    pub fn transaction_inclusion_proofs(
        &self,
    ) -> Vec<
        NArySparsePath<
            TRANSACTION_TREE_ARITY,
            TransactionTreeConfig<FS1::TranscriptField>,
            SparseNAryTransactionTreeConfig<FS1::TranscriptField>,
        >,
    > {
        (0..self.transactions.len())
            .map(|i| self.transaction_tree.generate_proof(i))
            .collect::<Result<_, _>>()
            .unwrap()
    }

    pub fn process_transaction_validity_proofs(
        &mut self,
        proofs: Vec<Option<(FS1::RW, FS1::RU, FS1::IU, FS1::Proof<1, 1>)>>,
        block_root: FS1::TranscriptField,
    ) -> (
        usize,
        AggregatorCircuitState<FS1, FS2>,
        AggregatorCircuitState<FS1, FS2>,
        <CycleFoldBasedIVC<FS1, FS2, T> as IVC>::Proof<AggregatorCircuit<T, FS1, FS2, ThreadRng>>,
        FS1::RW,
        FS2::RW,
    ) {
        let mut valid_indexes = vec![];
        let mut valid_proofs = vec![];

        for (i, ((tx, proof), sender)) in self
            .transactions
            .iter()
            .zip(proofs.into_iter())
            .zip(&self.senders)
            .enumerate()
        {
            if proof.is_none() {
                continue;
            }
            if tx
                .input_nullifiers
                .iter()
                .any(|i| !i.value.is_zero() && self.nullifiers.contains_key(&i.value))
            {
                continue;
            }
            let (WW, U, u, pi) = proof.unwrap();
            if u.public_inputs()
                != &[
                    &[*sender][..],
                    &tx.input_nullifiers
                        .iter()
                        .map(|i| i.value)
                        .collect::<Vec<_>>(),
                    &tx.output_utxo_commitments[..],
                    &[block_root],
                ]
                .concat()
            {
                continue;
            }
            let hash = T::new_with_pp_hash(&self.circuit.hash_config, self.circuit.pp_hash);
            let mut transcript1 = hash.separate_domain("transcript1".as_ref());
            let UU = FS1::verify(
                self.circuit.dk1.to_vk(),
                &mut transcript1,
                &[U.clone()],
                &[u.clone()],
                &pi,
            )
            .unwrap();

            if FS1::decide_running(&self.circuit.dk1, &WW, &UU).is_err() {
                continue;
            }
            valid_indexes.push(i);
            valid_proofs.push((WW, U, u, pi));
        }

        let initial_state = AggregatorCircuitState::<FS1, FS2> {
            V: FS1::RU::dummy(self.circuit.dk1.to_arith_config()),
            cf_U: FS2::RU::dummy(self.circuit.dk2.to_arith_config()),
            tx_index: valid_indexes[0],
            tx_root: self.transaction_tree.root(),
            nullifier_root: self.nullifier_tree.root(),
            signer_root: self.signer_tree.root(),
            block_root,
        };

        let mut prover = IVCStatefulProver::<_, CycleFoldBasedIVC<FS1, FS2, T>>::new(
            &self.pk,
            &self.circuit,
            initial_state,
        )
        .unwrap();

        let mut Y = FS1::RW::dummy(self.circuit.dk1.to_arith_config());
        let mut cf_W = FS2::RW::dummy(self.circuit.dk2.to_arith_config());
        let mut rng = thread_rng();

        let mut rng1 = test_rng();

        for (i, (WW, U, u, pi)) in valid_proofs.into_iter().enumerate() {
            let tx_index = valid_indexes[i];

            let mut nullifier_intervals = vec![];
            let mut nullifier_tree_replacement_proofs = vec![];
            let mut nullifier_tree_insertion_proofs = vec![];
            let mut nullifier_tree_replacement_positions = vec![];
            let mut nullifier_tree_insertion_positions = vec![];
            for nullifier in &self.transactions[tx_index].input_nullifiers {
                if nullifier.value.is_zero() {
                    nullifier_intervals
                        .push((-FS1::TranscriptField::one(), FS1::TranscriptField::one()));
                    nullifier_tree_replacement_positions.push(0);
                    nullifier_tree_insertion_positions.push(0);
                    nullifier_tree_replacement_proofs
                        .push(self.nullifier_tree.generate_membership_proof(0).unwrap());
                    nullifier_tree_insertion_proofs
                        .push(self.nullifier_tree.generate_membership_proof(0).unwrap());
                } else {
                    let (lb, (_, pos_lb)) = self
                        .nullifiers
                        .range((Unbounded, Excluded(nullifier.value)))
                        .next_back()
                        .map(|(k, v)| (*k, *v))
                        .unwrap();
                    let (ub, (pos_ub, _)) = self
                        .nullifiers
                        .range((Excluded(nullifier.value), Unbounded))
                        .next()
                        .map(|(k, v)| (*k, *v))
                        .unwrap();
                    assert_eq!(pos_lb, pos_ub);
                    let new_pos = self.nullifiers.len() + 1;

                    nullifier_intervals.push((lb, ub));
                    nullifier_tree_replacement_positions.push(pos_lb);
                    nullifier_tree_insertion_positions.push(new_pos);
                    nullifier_tree_replacement_proofs.push(
                        self.nullifier_tree
                            .update_and_prove(pos_lb, &(lb, nullifier.value))
                            .unwrap(),
                    );
                    nullifier_tree_insertion_proofs.push(
                        self.nullifier_tree
                            .update_and_prove(new_pos, &(nullifier.value, ub))
                            .unwrap(),
                    );

                    self.nullifiers.insert(nullifier.value, (pos_lb, new_pos));
                    self.nullifiers.get_mut(&ub).unwrap().0 = new_pos;
                }
            }

            let external_outputs = prover
                .prove_step(
                    AggregatorCircuitExternalInputs {
                        Y,
                        cf_W,

                        WW,
                        U,
                        u,
                        proof: pi,

                        pk: self.senders[tx_index],
                        tx: self.transactions[tx_index].clone(),

                        nullifier_intervals: nullifier_intervals.try_into().unwrap(),

                        next_tx_index: valid_indexes.get(i + 1).cloned().unwrap_or(usize::MAX),
                        tx_tree_inclusion_proof: self
                            .transaction_tree
                            .generate_proof(tx_index)
                            .unwrap(),
                        nullifier_tree_replacement_proofs: nullifier_tree_replacement_proofs
                            .try_into()
                            .unwrap(),
                        nullifier_tree_insertion_proofs: nullifier_tree_insertion_proofs
                            .try_into()
                            .unwrap(),
                        nullifier_tree_replacement_positions: nullifier_tree_replacement_positions
                            .try_into()
                            .unwrap(),
                        nullifier_tree_insertion_positions: nullifier_tree_insertion_positions
                            .try_into()
                            .unwrap(),
                        signer_tree_inclusion_proof: self
                            .signer_tree
                            .generate_proof(tx_index)
                            .unwrap(),
                        rng,
                    },
                    &mut rng1,
                )
                .unwrap();
            rng = external_outputs.rng;
            Y = external_outputs.YY;
            cf_W = external_outputs.cf_WW;
        }

        (
            prover.i,
            prover.initial_state,
            prover.current_state,
            prover.current_proof,
            Y,
            cf_W,
        )
    }
}

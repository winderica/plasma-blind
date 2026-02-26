use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::prelude::Boolean;
use ark_std::cmp::Ordering;
use plasmablind_core::primitives::crh::constraints::UTXOVarCRH;
use sonobe_primitives::algebra::ops::bits::ToBitsGadgetExt;
use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    sponge::Absorb,
};
use ark_r1cs_std::alloc::AllocVar;
use ark_std::rand::RngCore;
use nmerkle_trees::sparse::NArySparsePath;
use plasmablind_core::{
    config::{PlasmaBlindConfig, PlasmaBlindConfigVar},
    datastructures::{
        block::BlockMetadata,
        blocktree::BLOCK_TREE_ARITY,
        signerlist::{SignerTreeConfig, SparseNArySignerTreeConfig},
        txtree::{SparseNAryTransactionTreeConfig, TransactionTreeConfig, TRANSACTION_TREE_ARITY},
        utxo::UTXO,
    },
    primitives::{accumulator::constraints::Accumulator, crh::constraints::BlockTreeVarCRHGriffin},
};
use sonobe_fs::FoldingSchemeDef;
use sonobe_ivc::compilers::cyclefold::FoldingSchemeCycleFoldExt;
use sonobe_primitives::{circuits::FCircuit, commitments::VectorCommitmentDef};

use crate::circuits::{
    balance_inputs::{BalanceAux, BalanceAuxVar},
    balance_state::{BalanceState, BalanceStateVar},
};

pub struct BalanceCircuit<
    FS1: FoldingSchemeDef,
    H: TwoToOneCRHScheme,
    HG: TwoToOneCRHSchemeGadget<H, FS1::TranscriptField>,
    A: Accumulator<FS1::TranscriptField, H, HG>,
> {
    pub config: PlasmaBlindConfig<FS1::TranscriptField>,
    pub pp_hash: <FS1::VC as VectorCommitmentDef>::Scalar,
    pub acc_pp: HG::ParametersVar, // public parameters for the accumulator might not be poseidon
    pub _r: PhantomData<(H, A)>,
}

impl<
        FS1: FoldingSchemeCycleFoldExt<2, 0, TranscriptField: Absorb>,
        H: TwoToOneCRHScheme,
        HG: TwoToOneCRHSchemeGadget<H, FS1::TranscriptField>,
        A: Accumulator<FS1::TranscriptField, H, HG>,
    > FCircuit for BalanceCircuit<FS1, H, HG, A>
{
    type Field = <FS1::VC as VectorCommitmentDef>::Scalar;
    type State = BalanceState<FS1>;
    type StateVar = BalanceStateVar<FS1>;
    type ExternalInputs = BalanceAux<FS1>;
    type ExternalOutputs = PhantomData<FS1>;

    fn dummy_state(&self) -> Self::State {
        BalanceState {
            balance: FS1::TranscriptField::default(),
            nonce: FS1::TranscriptField::default(),
            pk: FS1::TranscriptField::default(),
            acc: FS1::TranscriptField::default(),
            block_hash: FS1::TranscriptField::default(),
            block_number: FS1::TranscriptField::default(),
            processed_tx_index: FS1::TranscriptField::default(),
        }
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {
        BalanceAux {
            block: BlockMetadata::default(),
            from: FS1::TranscriptField::default(),
            utxo_tree_root: FS1::TranscriptField::default(),
            tx_index: FS1::TranscriptField::default(),
            shielded_tx_utxos: vec![UTXO::dummy()],
            shielded_tx_utxos_proofs: vec![(
                vec![FS1::TranscriptField::default()],
                FS1::TranscriptField::default(),
            )],
            openings_mask: vec![bool::default()],
            shielded_tx_inclusion_proof: NArySparsePath::<
                TRANSACTION_TREE_ARITY,
                TransactionTreeConfig<FS1::TranscriptField>,
                SparseNAryTransactionTreeConfig<FS1::TranscriptField>,
            >::default(),
            signer_pk_inclusion_proof: NArySparsePath::<
                BLOCK_TREE_ARITY,
                SignerTreeConfig<FS1::TranscriptField>,
                SparseNArySignerTreeConfig<FS1::TranscriptField>,
            >::default(),
        }
    }

    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ark_relations::gr1cs::ConstraintSystemRef<Self::Field>,
        i: ark_r1cs_std::fields::fp::FpVar<Self::Field>,
        z_i: Self::StateVar,
        external_inputs: Self::ExternalInputs, // inputs that are not part of the state
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), ark_relations::gr1cs::SynthesisError> {
        let config_var = PlasmaBlindConfigVar::new_constant(cs.clone(), self.config.clone())?;

        let BalanceStateVar {
            balance,
            nonce,
            pk,
            acc,
            block_hash,
            block_number,
            processed_tx_index,
        } = z_i;

        let BalanceAuxVar {
            block,
            from,
            utxo_tree_root,
            tx_index,
            shielded_tx_utxos,
            shielded_tx_utxos_proofs,
            openings_mask,
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof,
        } = BalanceAuxVar::new_witness(cs, || Ok(external_inputs))?;

        // compute block hash and update accumulator value
        let next_block_hash =
            BlockTreeVarCRHGriffin::evaluate(&config_var.block_tree_leaf_config, &block)?;
        let next_acc = A::update(&self.acc_pp, &acc, &block_hash)?;

        // ensure the current processed block number is equal or greater than the previous block
        let next_block_number = block.height.to_fp()?;
        (&next_block_number - block_number).to_n_bits_le(64)?;

        // ensure that the processed tx has greater tx index (when processing same block)
        let next_tx_index = tx_index;
        let is_same_block = next_block_hash.is_eq(&block_hash)?;
        let is_higher_tx_index =
            &next_tx_index.is_cmp(&processed_tx_index, Ordering::Greater, false)?;
        is_higher_tx_index.conditional_enforce_equal(&Boolean::Constant(true), &is_same_block)?;

        // check that shielded tx is in tx tree
        shielded_tx_inclusion_proof
            .verify_membership(
                &(),
                &config_var.tx_tree_n_to_one_config,
                &block.tx_tree_root,
                &utxo_tree_root,
            )?
            .enforce_equal(&Boolean::constant(true))?;

        // check that the signer bit is 1 for the corresponding transaction (i.e. pk is included)
        signer_pk_inclusion_proof
            .verify_membership(
                &(),
                &config_var.signer_tree_n_to_one_config,
                &block.signer_tree_root,
                &from,
            )?
            .enforce_equal(&Boolean::Constant(true))?;

        // validity of input utxos is already checked by the transaction validity circuit and the
        // aggregator, so we only need to process the output utxos?
        // note that the transaction validity circuit ensures that sum(inputs) == sum(outputs)
        let is_sender = pk.is_eq(&from)?;
        let next_nonce = nonce + &is_sender.clone().into();
        let mut next_balance = balance;

        // if the user is the sender, he should provide data for all the output utxos
        // if the user is not the sender, he should provide data for the output utxos sent to him
        for ((is_opened, utxo), utxo_proof) in openings_mask
            .iter()
            .zip(shielded_tx_utxos)
            .zip(shielded_tx_utxos_proofs)
        {
            let is_in_tree = config_var.utxo_tree.is_at_index(
                &utxo_tree_root,
                &UTXOVarCRH::evaluate(&config_var.utxo_crh_config, &utxo)?,
                &utxo_proof.1,
                &utxo_proof.0,
            )?;

            let is_valid_utxo = is_opened & is_in_tree;
            Boolean::Constant(true).conditional_enforce_equal(&is_valid_utxo, &is_sender)?;

            let is_receiver = utxo.pk.is_eq(&pk)?;
            let increase_balance = is_receiver.clone() & is_valid_utxo.clone();
            let decrease_balance = is_sender.clone() & is_valid_utxo;
            next_balance += utxo.amount.to_fp()? * &increase_balance.into();
            next_balance -= utxo.amount.to_fp()? * &decrease_balance.into();
        }
        Ok((
            BalanceStateVar {
                balance: next_balance,
                nonce: next_nonce,
                pk,
                acc: next_acc,
                block_hash: next_block_hash,
                block_number: next_block_number,
                processed_tx_index: next_tx_index,
            },
            PhantomData::<FS1>,
        ))
    }
}

#[cfg(test)]
pub mod tests {

    use std::collections::BTreeMap;

    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::{
        poseidon::{constraints::CRHParametersVar, CRH},
        CRHScheme,
    };
    use ark_ff::{Field, UniformRand};
    use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;
    use plasmablind_core::{
        config::PlasmaBlindConfig,
        datastructures::{
            block::BlockMetadata,
            blocktree::BLOCK_TREE_ARITY,
            shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
            signerlist::{SparseNArySignerTree, SIGNER_TREE_ARITY},
            transparenttx::TransparentTransaction,
            txtree::{SparseNAryTransactionTree, TRANSACTION_TREE_ARITY},
            utxo::UTXO,
            TX_IO_SIZE,
        },
        primitives::{
            crh::{
                poseidon_canonical_config,
                utils::{
                    initialize_griffin_config, initialize_n_to_one_config_griffin,
                    initialize_poseidon_config, initialize_two_to_one_binary_tree_poseidon_config,
                },
                BlockTreeCRHGriffin, IntervalCRH, UTXOCRH,
            },
            sparsemt::MerkleSparseTree,
        },
    };
    use sonobe_primitives::commitments::pedersen::Pedersen;

    use crate::circuits::{
        balance_inputs::{BalanceAux, BalanceAuxVar},
        balance_state::{BalanceState, BalanceStateVar},
    };

    use sonobe_fs::{nova::Nova, ova::CycleFoldOva};

    use ark_bn254::G1Projective as C1;
    use ark_grumpkin::Projective as C2;

    #[test]
    pub fn test_balance_proving_step() {
        type FS1 = Nova<Pedersen<C1, true>>;
        type FS2 = CycleFoldOva<Pedersen<C2, true>>;

        let mut rng = test_rng();
        let pp = poseidon_canonical_config::<Fr>();

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

        let sender_sk = Fr::rand(&mut rng);
        let sender_pk = CRH::evaluate(&config.poseidon_config, vec![sender_sk]).unwrap();
        let receiver_sk = Fr::rand(&mut rng);
        let receiver_pk = CRH::evaluate(&config.poseidon_config, vec![receiver_sk]).unwrap();
        let tx = TransparentTransaction {
            inputs: [UTXO::new(sender_pk, 10, Fr::rand(&mut rng)); TX_IO_SIZE],
            inputs_info: [Default::default(); TX_IO_SIZE],
            // TODO: use also TX_IO_SIZE here, not sure how yet
            outputs: [
                UTXO::new(sender_pk, 10, Fr::rand(&mut rng)),
                UTXO::new(sender_pk, 10, Fr::rand(&mut rng)),
                UTXO::new(sender_pk, 10, Fr::rand(&mut rng)),
                UTXO::new(receiver_pk, 10, Fr::rand(&mut rng)),
            ],
        };
        let shielded_tx = ShieldedTransaction::new(
            &config.griffin_config,
            &config.utxo_crh_config,
            &sender_sk,
            &tx,
        )
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
        let shielded_tx_utxos_proofs = (0..4)
            .map(|idx| {
                (
                    utxo_tree.generate_membership_proof(idx).unwrap(),
                    Fr::from(idx as u64),
                )
            })
            .collect::<Vec<_>>();
        let shielded_tx_inclusion_proof = transaction_tree.generate_proof(1).unwrap();
        let signer_inclusion_proof = signer_tree.generate_proof(1).unwrap();
        let sender_aux = BalanceAux::<FS1> {
            block,
            from: sender_pk,
            utxo_tree_root: utxo_tree.root(),
            tx_index: Fr::ONE,
            shielded_tx_utxos: tx.outputs.to_vec(), // only outputs are processed
            shielded_tx_utxos_proofs,
            openings_mask: vec![true; 4],
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof: signer_inclusion_proof,
        };

        let cs = ConstraintSystem::new_ref();
        let sender_aux_var =
            BalanceAuxVar::new_variable(cs.clone(), || Ok(sender_aux), AllocationMode::Witness)
                .unwrap();

        let cur_balance = Fr::from(47);
        let cur_nonce = Fr::from(11);
        let pk = sender_pk;
        let cur_acc = Fr::from(13);
        let cur_block_hash = Fr::from(42);
        let cur_block_num = Fr::from(0);
        let cur_tx_index = Fr::from(0);

        let z_i = BalanceState::<FS1> {
            balance: cur_balance,
            nonce: cur_nonce,
            pk,
            acc: cur_acc,
            block_hash: cur_block_hash,
            block_number: cur_block_num,
            processed_tx_index: cur_tx_index,
        };
        let z_i_var =
            BalanceStateVar::new_variable(cs.clone(), || Ok(z_i), AllocationMode::Witness).unwrap();

        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();
    }
}

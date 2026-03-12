use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    sponge::Absorb,
};
use ark_r1cs_std::{
    alloc::AllocVar,
    cmp::CmpGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::Boolean,
    uint64::UInt64,
};
use ark_std::cmp::Ordering;
use plasmablind_core::{
    config::{PlasmaBlindConfig, PlasmaBlindConfigVar},
    datastructures::{
        block::BlockMetadata, shieldedtx::UTXOTree, signerlist::SparseNArySignerTree,
        txtree::SparseNAryTransactionTree, utxo::UTXO, TX_IO_SIZE,
    },
    primitives::crh::{
        constraints::{BlockTreeVarCRH, UTXOVarCRH},
        utils::Init,
    },
};
use sonobe_fs::FoldingSchemeDef;
use sonobe_ivc::compilers::cyclefold::FoldingSchemeCycleFoldExt;
use sonobe_primitives::{
    algebra::ops::bits::ToBitsGadgetExt, circuits::FCircuit, commitments::VectorCommitmentDef,
};

use crate::balance::{
    balance_inputs::{BalanceAux, BalanceAuxVar},
    balance_state::{BalanceState, BalanceStateVar},
};

pub struct BalanceCircuit<Cfg: Init> {
    pub config: PlasmaBlindConfig<Cfg>,
}

impl<Cfg: Init> FCircuit for BalanceCircuit<Cfg> {
    type Field = Cfg::F;
    type State = BalanceState<Cfg::F>;
    type StateVar = BalanceStateVar<Cfg::F>;
    type ExternalInputs = BalanceAux<Cfg>;
    type ExternalOutputs = ();

    fn dummy_state(&self) -> Self::State {
        BalanceState {
            balance: Default::default(),
            nonce: Default::default(),
            pk: Default::default(),
            acc: Default::default(),
            block_hash: Default::default(),
            block_number: Default::default(),
            processed_tx_index: Default::default(),
        }
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {
        let dummy_tx_tree = SparseNAryTransactionTree::blank(
            &self.config.tx_tree_leaf_config,
            &self.config.tx_tree_n_to_one_config,
            &Default::default(),
        )
        .unwrap();
        let dummy_shielded_tx_inclusion_proof = dummy_tx_tree.generate_proof(1).unwrap();
        let dummy_signer_tree = SparseNArySignerTree::blank(
            &self.config.signer_tree_leaf_config,
            &self.config.signer_tree_n_to_one_config,
            &Default::default(),
        )
        .unwrap();
        let dummy_signer_inclusion_proof = dummy_signer_tree.generate_proof(0).unwrap();
        let block = BlockMetadata {
            tx_tree_root: dummy_tx_tree.root,
            signer_tree_root: dummy_signer_tree.root,
            nullifier_tree_root: Default::default(),
            height: 0,
        };
        let dummy_utxo_tree = UTXOTree::blank(&(), &self.config.hash_config);
        let dummy_utxo_proof = dummy_utxo_tree.generate_membership_proof(0).unwrap();
        BalanceAux {
            block,
            from: From::from(1),
            utxo_tree_root: Default::default(),
            shielded_tx_utxos: vec![UTXO::dummy(); TX_IO_SIZE],
            shielded_tx_utxos_proofs: vec![(dummy_utxo_proof, Default::default()); TX_IO_SIZE],
            openings_mask: vec![false; TX_IO_SIZE],
            shielded_tx_inclusion_proof: dummy_shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof: dummy_signer_inclusion_proof,
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
            shielded_tx_utxos,
            shielded_tx_utxos_proofs,
            openings_mask,
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof,
        } = BalanceAuxVar::new_witness(cs, || Ok(external_inputs))?;

        // compute block hash and update accumulator value
        let next_block_hash =
            BlockTreeVarCRH::<Cfg>::evaluate(&config_var.block_tree_leaf_config, &block)?;
        let next_acc =
            Cfg::HGadget::evaluate(&config_var.hash_config, &[acc.clone(), block_hash.clone()])?;

        // ensure the current processed block number is equal or greater than the previous block
        let next_block_number = block.height;
        (&next_block_number.to_fp()? - block_number.to_fp()?).to_n_bits_le(64)?;

        // ensure that the processed tx has greater tx index (when processing same block)
        let (next_tx_index, rest) = UInt64::from_fp(&shielded_tx_inclusion_proof.index)?;
        rest.enforce_equal(&FpVar::zero())?;
        let is_different_block = next_block_hash.is_neq(&block_hash)?;
        let is_higher_tx_index = next_tx_index.is_gt(&processed_tx_index)?;
        (is_different_block | is_higher_tx_index).enforce_equal(&Boolean::TRUE)?;

        // check that shielded tx is in tx tree
        shielded_tx_inclusion_proof
            .calculate_root(&(), &config_var.tx_tree_n_to_one_config, &utxo_tree_root)?
            .enforce_equal(&block.tx_tree_root)?;

        // check that the signer bit is 1 for the corresponding transaction (i.e. pk is included)
        signer_pk_inclusion_proof
            .calculate_root(&(), &config_var.signer_tree_n_to_one_config, &from)?
            .enforce_equal(&block.signer_tree_root)?;

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
                &UTXOVarCRH::<Cfg>::evaluate(&config_var.utxo_crh_config, &utxo)?,
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
            (),
        ))
    }
}

#[cfg(test)]
pub mod tests {

    use std::{collections::BTreeMap, sync::Arc};

    use ark_bn254::{Fr, G1Projective as C1};
    use ark_crypto_primitives::{
        crh::{
            poseidon::{constraints::CRHParametersVar, CRH},
            CRHScheme,
        },
        sponge::poseidon::PoseidonConfig,
    };
    use ark_ff::{Field, UniformRand, Zero};
    use ark_grumpkin::Projective as C2;
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
            crh::{poseidon_canonical_config, utils::Init, BlockTreeCRH, IntervalCRH, UTXOCRH},
            sparsemt::MerkleSparseTree,
        },
    };
    use sonobe_fs::{nova::Nova, ova::CycleFoldOva};
    use sonobe_ivc::{compilers::cyclefold::CycleFoldBasedIVC, IVCStatefulProver, IVC};
    use sonobe_primitives::{
        commitments::pedersen::Pedersen,
        transcripts::griffin::{sponge::GriffinSponge, GriffinParams},
    };

    use crate::balance::{
        balance_inputs::{BalanceAux, BalanceAuxVar},
        balance_state::{BalanceState, BalanceStateVar},
        circuit::BalanceCircuit,
    };

    pub fn test_balance_proving_step_opt<Cfg: Init<F = Fr>>() {
        type FS1 = Nova<Pedersen<C1, true>>;
        type FS2 = CycleFoldOva<Pedersen<C2, true>>;
        type T = GriffinSponge<Fr>;

        let mut rng = test_rng();
        let pp = poseidon_canonical_config::<Fr>();

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
        let shielded_tx = ShieldedTransaction::new(
            &config.hash_config,
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
        let mut sender_aux = BalanceAux::<Cfg> {
            block,
            from: sender_pk,
            utxo_tree_root: utxo_tree.root(),
            shielded_tx_utxos: tx.outputs.to_vec(), // only outputs are processed
            shielded_tx_utxos_proofs,
            openings_mask: vec![true; TX_IO_SIZE],
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof: signer_inclusion_proof,
        };

        let cur_balance = 10000000;
        let cur_nonce = Fr::from(11);
        let pk = sender_pk;
        let cur_acc = Fr::from(13);
        let cur_block_hash = Fr::from(42);
        let cur_block_num = 0;
        let cur_tx_index = 0;

        let z_i = BalanceState {
            balance: cur_balance,
            nonce: cur_nonce,
            pk,
            acc: cur_acc,
            block_hash: cur_block_hash,
            block_number: cur_block_num,
            processed_tx_index: cur_tx_index,
        };

        let circuit = BalanceCircuit { config };

        let mut rng1 = test_rng();
        let hash_config = Arc::new(GriffinParams::new(16, 5, 9));
        let pp = CycleFoldBasedIVC::<FS1, FS2, T>::preprocess(
            (1 << 19, (2048, 2048), hash_config.clone()),
            &mut rng1,
        )
        .unwrap();
        let (pk, vk) = CycleFoldBasedIVC::<FS1, FS2, T>::generate_keys(pp, &circuit).unwrap();

        let mut prover =
            IVCStatefulProver::<_, CycleFoldBasedIVC<FS1, FS2, T>>::new(&pk, &circuit, z_i)
                .unwrap();

        for _ in 0..10 {
            prover.prove_step(sender_aux.clone(), &mut rng).unwrap();
            sender_aux.block.height += 1;
        }

        CycleFoldBasedIVC::<FS1, FS2, T>::verify::<BalanceCircuit<Cfg>>(
            &vk,
            prover.i,
            &prover.initial_state,
            &prover.current_state,
            &prover.current_proof,
        )
        .unwrap();
    }

    #[test]
    fn test_balance_proving_step() {
        test_balance_proving_step_opt::<PoseidonConfig<Fr>>();
        test_balance_proving_step_opt::<GriffinParams<Fr>>();
    }
}

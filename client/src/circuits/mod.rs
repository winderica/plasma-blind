use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHParametersVar, TwoToOneCRHGadget},
            TwoToOneCRH,
        },
        CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    },
    merkle_tree::constraints::PathVar,
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use nmerkle_trees::sparse::constraints::NArySparsePathVar;
use plasmablind_core::{
    config::{PlasmaBlindConfig, PlasmaBlindConfigVar},
    datastructures::{
        block::constraints::BlockMetadataVar,
        keypair::constraints::PublicKeyVar,
        shieldedtx::{
            constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
            ShieldedTransactionConfig,
        },
        signerlist::{
            constraints::{SignerTreeConfigGadget, SparseNArySignerTreeConfigGadget},
            SignerTreeConfig, SparseNArySignerTreeConfig, SIGNER_TREE_ARITY,
        },
        txtree::{
            constraints::{SparseNAryTransactionTreeConfigGadget, TransactionTreeConfigGadget},
            SparseNAryTransactionTreeConfig, TransactionTreeConfig, TRANSACTION_TREE_ARITY,
        },
        utxo::constraints::UTXOVar,
    },
    primitives::{
        accumulator::constraints::Accumulator,
        crh::{
            constraints::{BlockTreeVarCRH, BlockTreeVarCRHGriffin, PublicKeyVarCRH, UTXOVarCRH},
            PublicKeyCRH,
        },
        sparsemt::{constraints::SparseConfigGadget, SparseConfig},
    },
};
use sonobe_primitives::{algebra::ops::bits::ToBitsGadgetExt, transcripts::Absorbable};
use std::{borrow::Borrow, cmp::Ordering, marker::PhantomData};

use crate::UserAux;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMaskVar<F> = Vec<Boolean<F>>;

pub struct UserCircuit<
    F: PrimeField + Absorb + Absorbable,
    H: TwoToOneCRHScheme,
    T: TwoToOneCRHSchemeGadget<H, F>,
    A: Accumulator<F, H, T>,
    const N_TX_PER_FOLD_STEP: usize,
> {
    _a: PhantomData<A>,
    acc_pp: T::ParametersVar, // public parameters for the accumulator might not be poseidon
    plasma_blind_config: PlasmaBlindConfigVar<F>,
}

impl<
        F: PrimeField + Absorb + Absorbable,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, F>,
        A: Accumulator<F, H, T>,
        const N_TX_PER_FOLD_STEP: usize,
    > UserCircuit<F, H, T, A, N_TX_PER_FOLD_STEP>
{
    pub fn new(acc_pp: T::ParametersVar, plasma_blind_config: PlasmaBlindConfigVar<F>) -> Self {
        Self {
            _a: PhantomData,
            acc_pp,
            plasma_blind_config,
        }
    }
}
// Process transaction-wise. For each tx:
// - get block content: (tx_tree, signer_tree) := block (not using the nullifier tree?) (ok)
// - get shielded tx content: shielded transaction, index in tree and utxo openings (ok)
// - show that shielded transaction is in tx tree (ok)
// - show that signer bit for committed_tx_root has been set to 1 (ok)
// - user is sender if transacation's pk is his pk (ok)
// - for each utxo:
//      - a utxo is valid when it is supposed to be opened and is in the shielded tx (ok)
//      - if user is sender, he should process all utxos (ok)
//      - if user is receiver and utxo is valid, increase balance (ok)
//      - if user is sender and utxo is valid, decrease balance (ok)
// - accumulate block hash
pub struct UserAuxVar<F: PrimeField + Absorb + Absorbable> {
    pub block: BlockMetadataVar<F>,
    pub from: FpVar<F>,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub utxo_tree_root: FpVar<F>,
    // index of transaction within transaction tree
    pub tx_index: FpVar<F>,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXOVar<F>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<(Vec<FpVar<F>>, FpVar<F>)>,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: OpeningsMaskVar<F>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof: NArySparsePathVar<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<F>,
        TransactionTreeConfigGadget<F>,
        F,
        SparseNAryTransactionTreeConfig<F>,
        SparseNAryTransactionTreeConfigGadget<F>,
    >,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof: NArySparsePathVar<
        SIGNER_TREE_ARITY,
        SignerTreeConfig<F>,
        SignerTreeConfigGadget<F>,
        F,
        SparseNArySignerTreeConfig<F>,
        SparseNArySignerTreeConfigGadget<F>,
    >,
}

impl<F: PrimeField + Absorb + Absorbable> AllocVar<UserAux<F>, F> for UserAuxVar<F> {
    fn new_variable<T: Borrow<UserAux<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let t = f()?;
        let user_aux = t.borrow();
        let block =
            BlockMetadataVar::new_variable(cs.clone(), || Ok(user_aux.block.clone()), mode)?;
        let from = FpVar::new_variable(cs.clone(), || Ok(user_aux.from), mode)?;
        let utxo_tree_root =
            FpVar::new_variable(cs.clone(), || Ok(user_aux.utxo_tree_root.clone()), mode)?;
        let tx_index = FpVar::new_variable(cs.clone(), || Ok(user_aux.tx_index), mode)?;
        let shielded_tx_utxos = Vec::<UTXOVar<_>>::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx_utxos.clone()),
            mode,
        )?;
        let shielded_tx_utxos_proofs = user_aux
            .shielded_tx_utxos_proofs
            .iter()
            .map(|i| {
                Ok((
                    Vec::new_variable(cs.clone(), || Ok(&i.0[..]), mode)?,
                    FpVar::new_variable(cs.clone(), || Ok(&i.1), mode)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let openings_mask =
            Vec::new_variable(cs.clone(), || Ok(user_aux.openings_mask.clone()), mode)?;
        let shielded_tx_inclusion_proof = NArySparsePathVar::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx_inclusion_proof.clone()),
            mode,
        )?;
        let signer_pk_inclusion_proof = NArySparsePathVar::new_variable(
            cs.clone(),
            || Ok(user_aux.signer_pk_inclusion_proof.clone()),
            mode,
        )?;
        Ok(UserAuxVar {
            block,
            from,
            utxo_tree_root,
            tx_index,
            shielded_tx_utxos,
            shielded_tx_utxos_proofs,
            openings_mask,
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof,
        })
    }
}

impl<
        F: PrimeField + Absorb + Absorbable,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, F>,
        A: Accumulator<F, H, T>,
        const N_TX_PER_FOLD_STEP: usize,
    > UserCircuit<F, H, T, A, N_TX_PER_FOLD_STEP>
{
    pub fn update_balance(
        &self,
        cs: ConstraintSystemRef<F>,
        z_i: Vec<FpVar<F>>,
        aux: UserAuxVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let (balance, nonce, pk, acc, block_hash, block_number, processed_tx_index) = (
            z_i[0].clone(),
            z_i[1].clone(),
            z_i[2].clone(),
            z_i[3].clone(),
            z_i[4].clone(),
            z_i[5].clone(),
            z_i[6].clone(),
        );

        // compute block hash and update accumulator value
        let next_block_hash = BlockTreeVarCRHGriffin::evaluate(
            &self.plasma_blind_config.block_tree_leaf_config,
            &aux.block,
        )?;
        let next_acc = A::update(&self.acc_pp, &acc, &block_hash)?;

        // ensure the current processed block number is equal or greater than the previous block
        let next_block_number = aux.block.height.to_fp()?;
        (&next_block_number - block_number).to_n_bits_le(64)?;

        // ensure that the processed tx has greater tx index (when processing same block)
        let next_tx_index = aux.tx_index;
        let is_same_block = next_block_hash.is_eq(&block_hash)?;
        let is_higher_tx_index =
            &next_tx_index.is_cmp(&processed_tx_index, Ordering::Greater, false)?;
        is_higher_tx_index.conditional_enforce_equal(&Boolean::Constant(true), &is_same_block)?;

        // check that shielded tx is in tx tree
        aux.shielded_tx_inclusion_proof
            .verify_membership(
                &(),
                &self.plasma_blind_config.tx_tree_n_to_one_config,
                &aux.block.tx_tree_root,
                &aux.utxo_tree_root,
            )?
            .enforce_equal(&Boolean::constant(true))?;

        // check that the signer bit is 1 for the corresponding transaction (i.e. pk is included)
        aux.signer_pk_inclusion_proof
            .verify_membership(
                &(),
                &self.plasma_blind_config.signer_tree_n_to_one_config,
                &aux.block.signer_tree_root,
                &aux.from,
            )?
            .enforce_equal(&Boolean::Constant(true))?;

        // validity of input utxos is already checked by the transaction validity circuit and the
        // aggregator, so we only need to process the output utxos?
        // note that the transaction validity circuit ensures that sum(inputs) == sum(outputs)
        let is_sender = pk.is_eq(&aux.from)?;
        let next_nonce = nonce + &is_sender.clone().into();
        let mut next_balance = balance;

        // if the user is the sender, he should provide data for all the output utxos
        // if the user is not the sender, he should provide data for the output utxos sent to him
        for ((is_opened, utxo), utxo_proof) in aux
            .openings_mask
            .iter()
            .zip(aux.shielded_tx_utxos)
            .zip(aux.shielded_tx_utxos_proofs)
        {
            let is_in_tree = self.plasma_blind_config.utxo_tree.is_at_index(
                &aux.utxo_tree_root,
                &UTXOVarCRH::evaluate(&self.plasma_blind_config.utxo_crh_config, &utxo)?,
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
        Ok(vec![
            next_balance,
            next_nonce,
            pk,
            next_acc,
            next_block_hash,
            next_block_number,
            next_tx_index,
        ])
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::{
            poseidon::{
                constraints::{CRHParametersVar, TwoToOneCRHGadget},
                TwoToOneCRH, CRH,
            },
            CRHScheme,
        },
        merkle_tree::MerkleTree,
        sponge::poseidon::PoseidonConfig,
    };
    use ark_ff::{Field, UniformRand};
    use ark_grumpkin::{constraints::GVar as ProjectiveVar, Projective};
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        GR1CSVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{rand::RngCore, test_rng};
    use plasmablind_core::{
        datastructures::{
            block::{Block, BlockMetadata},
            blocktree::BLOCK_TREE_ARITY,
            nullifier::Nullifier,
            shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
            signerlist::{
                constraints::SignerTreeConfigGadget, SignerTree, SignerTreeConfig,
                SparseNArySignerTree,
            },
            transparenttx::TransparentTransaction,
            txtree::{
                constraints::TransactionTreeConfigGadget, SparseNAryTransactionTree,
                TransactionTree, TransactionTreeConfig,
            },
            user::User,
            utxo::UTXO,
            TX_IO_SIZE,
        },
        primitives::{
            accumulator::constraints::PoseidonAccumulatorVar,
            crh::{
                poseidon_canonical_config,
                utils::{
                    initialize_griffin_config, initialize_n_to_one_config_griffin,
                    initialize_poseidon_config, initialize_two_to_one_binary_tree_poseidon_config,
                },
                BlockTreeCRH, BlockTreeCRHGriffin, IntervalCRH, PublicKeyCRH, UTXOCRH,
            },
            sparsemt::MerkleSparseTree,
        },
    };

    use super::*;
    use crate::UserAux;

    #[test]
    pub fn test_user_circuit() {
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
            inputs: [
                UTXO::new(sender_pk, 10, Fr::rand(&mut rng)),
                UTXO::new(sender_pk, 10, Fr::rand(&mut rng)),
                UTXO::new(sender_pk, 10, Fr::rand(&mut rng)),
                UTXO::new(sender_pk, 10, Fr::rand(&mut rng)),
            ],
            inputs_info: [Default::default(); TX_IO_SIZE],
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
        let sender_aux = UserAux {
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
            UserAuxVar::new_variable(cs.clone(), || Ok(sender_aux), AllocationMode::Witness)
                .unwrap();

        let cur_balance = Fr::from(47);
        let cur_nonce = Fr::from(11);
        let pk = sender_pk;
        let cur_acc = Fr::from(13);
        let cur_block_hash = Fr::from(42);
        let cur_block_num = Fr::from(0);
        let cur_tx_index = Fr::from(0);

        let z_i = vec![
            cur_balance,
            cur_nonce,
            pk,
            cur_acc,
            cur_block_hash,
            cur_block_num,
            cur_tx_index,
        ];
        let z_i_var = Vec::new_variable(cs.clone(), || Ok(z_i), AllocationMode::Witness).unwrap();

        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();
        let user_circuit = UserCircuit::<
            Fr,
            TwoToOneCRH<Fr>,
            TwoToOneCRHGadget<Fr>,
            PoseidonAccumulatorVar<Fr>,
            1,
        >::new(
            pp_var.clone(),
            PlasmaBlindConfigVar::new_constant(cs.clone(), config).unwrap(),
        );

        let new_z_i_var = user_circuit
            .update_balance(cs.clone(), z_i_var, sender_aux_var)
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(new_z_i_var[0].value().unwrap(), cur_balance - Fr::from(10)); // balance should
                                                                                 // decrease by 10
        assert_eq!(new_z_i_var[1].value().unwrap(), cur_nonce + Fr::ONE); // nonce increased by 1
        assert_eq!(new_z_i_var[2].value().unwrap(), pk); // pk hash is invariant
        assert_ne!(new_z_i_var[3].value().unwrap(), cur_acc); // accumulator changed
        assert_ne!(new_z_i_var[4].value().unwrap(), cur_block_hash); // block hash is new
        assert_eq!(new_z_i_var[5].value().unwrap(), Fr::ONE); // block num is changed
        assert!(new_z_i_var[6].value().unwrap() > cur_tx_index); // greater tx index
    }
}

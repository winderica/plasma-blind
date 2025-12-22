use std::{borrow::Borrow, cmp::Ordering, marker::PhantomData};

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
use plasmablind_core::{
    config::{PlasmaBlindConfig, PlasmaBlindConfigVar},
    datastructures::{
        block::constraints::BlockVar,
        keypair::constraints::PublicKeyVar,
        shieldedtx::{
            constraints::{ShieldedTransactionConfigGadget, ShieldedTransactionVar},
            ShieldedTransactionConfig,
        },
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
        txtree::{constraints::TransactionTreeConfigGadget, TransactionTreeConfig},
        utxo::constraints::UTXOVar,
    },
    primitives::{
        accumulator::constraints::Accumulator,
        crh::{
            constraints::{BlockVarCRH, PublicKeyVarCRH, UTXOVarCRH},
            BlockCRH, PublicKeyCRH,
        },
        sparsemt::{constraints::SparseConfigGadget, SparseConfig},
    },
};

use crate::UserAux;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMaskVar<F> = Vec<Boolean<F>>;

pub struct UserCircuit<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    H: TwoToOneCRHScheme,
    T: TwoToOneCRHSchemeGadget<H, C::BaseField>,
    A: Accumulator<C::BaseField, H, T>,
    const N_TX_PER_FOLD_STEP: usize,
> {
    _a: PhantomData<A>,
    _f: PhantomData<C::BaseField>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
    acc_pp: T::ParametersVar, // public parameters for the accumulator might not be poseidon
    plasma_blind_config: PlasmaBlindConfigVar<C, CVar>,
}

impl<
        C: CurveGroup<BaseField: PrimeField + Absorb>,
        CVar: CurveVar<C, C::BaseField>,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, C::BaseField>,
        A: Accumulator<C::BaseField, H, T>,
        const N_TX_PER_FOLD_STEP: usize,
    > UserCircuit<C, CVar, H, T, A, N_TX_PER_FOLD_STEP>
{
    pub fn new(
        acc_pp: T::ParametersVar,
        plasma_blind_config: PlasmaBlindConfigVar<C, CVar>,
    ) -> Self {
        Self {
            _a: PhantomData,
            _f: PhantomData,
            _c: PhantomData,
            _cvar: PhantomData,
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
#[derive(Clone)]
pub struct UserAuxVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    pub block: BlockVar<C::BaseField>,
    pub from: PublicKeyVar<C, CVar>,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub utxo_tree_root: FpVar<C::BaseField>,
    // index of transaction within transaction tree
    pub tx_index: FpVar<C::BaseField>,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXOVar<C, CVar>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<(Vec<FpVar<C::BaseField>>, FpVar<C::BaseField>)>,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: OpeningsMaskVar<C::BaseField>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof: Vec<FpVar<C::BaseField>>,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof: Vec<FpVar<C::BaseField>>,
    pub signer_index: FpVar<C::BaseField>,
    pub pk: PublicKeyVar<C, CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<UserAux<C>, C::BaseField> for UserAuxVar<C, CVar>
{
    fn new_variable<T: Borrow<UserAux<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let t = f()?;
        let user_aux = t.borrow();
        let block = BlockVar::new_variable(cs.clone(), || Ok(user_aux.block.clone()), mode)?;
        let from = PublicKeyVar::new_variable(cs.clone(), || Ok(user_aux.from), mode)?;
        let utxo_tree_root =
            FpVar::new_variable(cs.clone(), || Ok(user_aux.utxo_tree_root.clone()), mode)?;
        let tx_index = FpVar::new_variable(cs.clone(), || Ok(user_aux.tx_index), mode)?;
        let shielded_tx_utxos = Vec::<UTXOVar<C, CVar>>::new_variable(
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
        let shielded_tx_inclusion_proof = AllocVar::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx_inclusion_proof.clone()),
            mode,
        )?;
        let signer_pk_inclusion_proof = AllocVar::new_variable(
            cs.clone(),
            || Ok(user_aux.signer_pk_inclusion_proof.clone()),
            mode,
        )?;
        let signer_index = FpVar::new_variable(cs.clone(), || Ok(user_aux.signer_index), mode)?;
        let pk = PublicKeyVar::new_variable(cs.clone(), || Ok(user_aux.pk), mode)?;
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
            signer_index,
            pk,
        })
    }
}

impl<
        C: CurveGroup<BaseField: PrimeField + Absorb>,
        CVar: CurveVar<C, C::BaseField>,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, C::BaseField>,
        A: Accumulator<C::BaseField, H, T>,
        const N_TX_PER_FOLD_STEP: usize,
    > UserCircuit<C, CVar, H, T, A, N_TX_PER_FOLD_STEP>
{
    pub fn update_balance(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        z_i: Vec<FpVar<C::BaseField>>,
        aux: UserAuxVar<C, CVar>,
    ) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError> {
        let (balance, nonce, pk_hash, acc, block_hash, block_number, processed_tx_index) = (
            z_i[0].clone(),
            z_i[1].clone(),
            z_i[2].clone(),
            z_i[3].clone(),
            z_i[4].clone(),
            z_i[5].clone(),
            z_i[6].clone(),
        );

        // ensure correct pk is provided in aux inputs
        let computed_pk_hash =
            <PublicKeyVarCRH<C, CVar> as CRHSchemeGadget<PublicKeyCRH<C>, _>>::evaluate(
                &self.plasma_blind_config.poseidon_config,
                &aux.pk,
            )?;
        computed_pk_hash.enforce_equal(&pk_hash)?;

        // compute block hash and update accumulator value
        let next_block_hash =
            BlockVarCRH::evaluate(&self.plasma_blind_config.block_crh_config, &aux.block)?;
        let next_acc = A::update(&self.acc_pp, &acc, &block_hash)?;

        // ensure the current processed block number is equal or greater than the previous block
        let next_block_number = aux.block.height;
        let _ = &block_number.enforce_cmp(&next_block_number, Ordering::Less, true)?;

        // ensure that the processed tx has greater tx index (when processing same block)
        let next_tx_index = aux.tx_index;
        let is_same_block = next_block_hash.is_eq(&block_hash)?;
        let is_higher_tx_index =
            &next_tx_index.is_cmp(&processed_tx_index, Ordering::Greater, false)?;
        is_higher_tx_index.conditional_enforce_equal(&Boolean::Constant(true), &is_same_block)?;

        // check that shielded tx is in tx tree
        self.plasma_blind_config.tx_tree.check_index(
            &aux.block.tx_tree_root,
            &aux.utxo_tree_root,
            &next_tx_index,
            &aux.shielded_tx_inclusion_proof,
        )?;

        // check that the signer bit is 1 for the corresponding transaction (i.e. pk is included)
        self.plasma_blind_config.signer_tree.check_index(
            &aux.block.signer_tree_root,
            &aux.from,
            &aux.signer_index,
            &aux.signer_pk_inclusion_proof,
        )?;

        // validity of input utxos is already checked by the transaction validity circuit and the
        // aggregator, so we only need to process the output utxos?
        // note that the transaction validity circuit ensures that sum(inputs) == sum(outputs)
        let is_sender = aux.pk.key.is_eq(&aux.from.key)?;
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

            let is_receiver = utxo.pk.key.is_eq(&aux.pk.key)?;
            let increase_balance = is_receiver.clone() & is_valid_utxo.clone();
            let decrease_balance = is_sender.clone() & is_valid_utxo;
            next_balance += utxo.amount.clone() * &increase_balance.into();
            next_balance -= utxo.amount * &decrease_balance.into();
        }
        Ok(vec![
            next_balance,
            next_nonce,
            pk_hash,
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
                TwoToOneCRH,
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
            block::Block,
            nullifier::Nullifier,
            shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
            signerlist::{constraints::SignerTreeConfigGadget, SignerTree, SignerTreeConfig},
            transparenttx::TransparentTransaction,
            txtree::{
                constraints::TransactionTreeConfigGadget, TransactionTree, TransactionTreeConfig,
            },
            user::User,
            utxo::UTXO,
        },
        primitives::{
            accumulator::constraints::PoseidonAccumulatorVar,
            crh::{
                poseidon_canonical_config,
                utils::{
                    initialize_poseidon_config, initialize_two_to_one_binary_tree_poseidon_config,
                },
                BlockCRH, BlockTreeCRH, PublicKeyCRH, UTXOCRH,
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

        let utxo_crh_config = <UTXOCRH<Projective> as CRHScheme>::setup(&mut rng).unwrap();
        let shielded_tx_leaf_config = ();
        let tx_tree_leaf_config = ();
        let signer_tree_leaf_config =
            <PublicKeyCRH<Projective> as CRHScheme>::setup(&mut rng).unwrap();
        let block_tree_leaf_config = <BlockTreeCRH<Fr> as CRHScheme>::setup(&mut rng).unwrap();

        let tx_tree_two_to_one_config = two_to_one_poseidon_config.clone();
        let shielded_tx_two_to_one_config = two_to_one_poseidon_config.clone();
        let signer_tree_two_to_one_config = two_to_one_poseidon_config.clone();
        let block_tree_two_to_one_config = two_to_one_poseidon_config.clone();

        let block_crh_config = <BlockCRH<Fr> as CRHScheme>::setup(&mut rng).unwrap();

        let config = PlasmaBlindConfig::<Projective>::new(
            poseidon_config.clone(),
            utxo_crh_config,
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

        let sender = User::new(&mut rng, 1);
        let sender_sk = Fr::rand(&mut rng);
        let receiver = User::new(&mut rng, 2);
        let tx = TransparentTransaction {
            inputs: [
                UTXO::new(sender.keypair.pk, 10, rng.next_u64() as u128, 0, None, None),
                UTXO::new(sender.keypair.pk, 10, rng.next_u64() as u128, 1, None, None),
                UTXO::new(sender.keypair.pk, 10, rng.next_u64() as u128, 2, None, None),
                UTXO::new(sender.keypair.pk, 10, rng.next_u64() as u128, 3, None, None),
            ],
            outputs: [
                UTXO::new(sender.keypair.pk, 10, rng.next_u64() as u128, 4, None, None),
                UTXO::new(sender.keypair.pk, 10, rng.next_u64() as u128, 5, None, None),
                UTXO::new(sender.keypair.pk, 10, rng.next_u64() as u128, 6, None, None),
                UTXO::new(
                    receiver.keypair.pk,
                    10,
                    rng.next_u64() as u128,
                    7,
                    None,
                    None,
                ),
            ],
        };
        let shielded_tx = ShieldedTransaction::new(
            &config.poseidon_config,
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

        let transactions = [
            Default::default(),
            utxo_tree.root(),
            Default::default(),
            Default::default(),
            Default::default(),
        ];

        let signer_tree = SignerTree::<SignerTreeConfig<Projective>>::new(
            &config.signer_tree_leaf_config,
            &config.signer_tree_two_to_one_config,
            &BTreeMap::from([(sender.id as usize, sender.keypair.pk)]),
        )
        .unwrap();
        let transaction_tree = TransactionTree::<TransactionTreeConfig<_>>::new(
            &(),
            &config.shielded_tx_two_to_one_config,
            &BTreeMap::from_iter(transactions.into_iter().enumerate()),
        )
        .unwrap();

        let block = Block {
            tx_tree_root: transaction_tree.root(),
            signer_tree_root: signer_tree.root(),
            nullifier_tree_root: Fr::default(),
            signers: vec![Some(sender.id)],
            height: 1,
            deposits: vec![],
            withdrawals: vec![],
        };
        let shielded_tx_utxos_proofs = (0..4)
            .map(|idx| {
                (
                    utxo_tree.generate_membership_proof(idx).unwrap(),
                    Fr::from(idx as u64),
                )
            })
            .collect::<Vec<_>>();
        let shielded_tx_inclusion_proof = transaction_tree.generate_membership_proof(1).unwrap();
        let signer_inclusion_proof = signer_tree
            .generate_membership_proof(sender.id as usize)
            .unwrap();
        let sender_aux = UserAux {
            block,
            from: sender.keypair.pk,
            utxo_tree_root: utxo_tree.root(),
            tx_index: Fr::ONE,
            shielded_tx_utxos: tx.outputs.to_vec(), // only outputs are processed
            shielded_tx_utxos_proofs,
            openings_mask: vec![true; 4],
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof: signer_inclusion_proof,
            signer_index: Fr::from(sender.id as u64),
            pk: sender.keypair.pk,
        };

        let cs = ConstraintSystem::new_ref();
        let sender_aux_var = UserAuxVar::<Projective, ProjectiveVar>::new_variable(
            cs.clone(),
            || Ok(sender_aux),
            AllocationMode::Witness,
        )
        .unwrap();

        let cur_balance = Fr::from(47);
        let cur_nonce = Fr::from(11);
        let pk_hash = PublicKeyCRH::evaluate(&pp, sender.keypair.pk).unwrap();
        let cur_acc = Fr::from(13);
        let cur_block_hash = Fr::from(42);
        let cur_block_num = Fr::from(0);
        let cur_tx_index = Fr::from(0);

        let z_i = vec![
            cur_balance,
            cur_nonce,
            pk_hash,
            cur_acc,
            cur_block_hash,
            cur_block_num,
            cur_tx_index,
        ];
        let z_i_var = Vec::new_variable(cs.clone(), || Ok(z_i), AllocationMode::Witness).unwrap();

        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();
        let user_circuit = UserCircuit::<
            Projective,
            ProjectiveVar,
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
        assert_eq!(new_z_i_var[2].value().unwrap(), pk_hash); // pk hash is invariant
        assert_ne!(new_z_i_var[3].value().unwrap(), cur_acc); // accumulator changed
        assert_ne!(new_z_i_var[4].value().unwrap(), cur_block_hash); // block hash is new
        assert_eq!(new_z_i_var[5].value().unwrap(), Fr::ONE); // block num is changed
        assert!(new_z_i_var[6].value().unwrap() > cur_tx_index); // greater tx index
    }
}

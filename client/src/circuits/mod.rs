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
use core::{
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
            constraints::{BlockVarCRH, PublicKeyVarCRH},
            BlockCRH, PublicKeyCRH,
        },
        sparsemt::{
            constraints::{MerkleSparseTreePathVar, SparseConfigGadget},
            SparseConfig,
        },
    },
};
use std::borrow::Borrow;
use std::{cmp::Ordering, marker::PhantomData};

use crate::UserAux;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMaskVar<F> = Vec<Boolean<F>>;
pub type UTXOInclusionProofVar<C, F, CVar> =
    PathVar<ShieldedTransactionConfig<C>, F, ShieldedTransactionConfigGadget<C, CVar>>;
pub type ShieldedTxInclusionProofVar<C, F, CVar> =
    MerkleSparseTreePathVar<TransactionTreeConfig<C>, F, TransactionTreeConfigGadget<C, CVar>>;
pub type SignerInclusionProofVar<C, F, CVar> =
    MerkleSparseTreePathVar<SignerTreeConfig<C>, F, SignerTreeConfigGadget<C, CVar>>;

#[derive(Clone)]
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
    pp: CRHParametersVar<C::BaseField>,
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
    pub fn new(acc_pp: T::ParametersVar, pp: CRHParametersVar<C::BaseField>) -> Self {
        Self {
            _a: PhantomData,
            _f: PhantomData,
            _c: PhantomData,
            _cvar: PhantomData,
            acc_pp,
            pp,
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
#[derive(Clone, Debug)]
pub struct UserAuxVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    TC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // transaction tree config
    TCG: SparseConfigGadget<
        TC,
        C::BaseField,
        InnerDigest = FpVar<C::BaseField>,
        TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
        LeafDigest = FpVar<C::BaseField>,
        Leaf = ShieldedTransactionVar<C, CVar>,
    >,
    SC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // signer tree config
    SCG: SparseConfigGadget<
        SC,
        C::BaseField,
        InnerDigest = FpVar<C::BaseField>,
        TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
        LeafDigest = FpVar<C::BaseField>,
        Leaf = PublicKeyVar<C, CVar>,
    >,
> {
    pub block: BlockVar<C, TC, TCG, SC, SCG>,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub shielded_tx: ShieldedTransactionVar<C, CVar>,
    // index of transaction within transaction tree
    pub tx_index: FpVar<C::BaseField>,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXOVar<C, CVar>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<UTXOInclusionProofVar<C, C::BaseField, CVar>>,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: OpeningsMaskVar<C::BaseField>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof: ShieldedTxInclusionProofVar<C, C::BaseField, CVar>,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof: SignerInclusionProofVar<C, C::BaseField, CVar>,
    pub pk: PublicKeyVar<C, CVar>,
}

impl<
        C: CurveGroup<BaseField: PrimeField + Absorb>,
        CVar: CurveVar<C, C::BaseField>,
        TC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // transaction tree config
        TCG: SparseConfigGadget<
            TC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = ShieldedTransactionVar<C, CVar>,
        >,
        SC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // signer tree config
        SCG: SparseConfigGadget<
            SC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = PublicKeyVar<C, CVar>,
        >,
    > AllocVar<UserAux<C>, C::BaseField> for UserAuxVar<C, CVar, TC, TCG, SC, SCG>
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
        let shielded_tx = ShieldedTransactionVar::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx.clone()),
            mode,
        )?;
        let tx_index = FpVar::new_variable(cs.clone(), || Ok(user_aux.tx_index), mode)?;
        let shielded_tx_utxos = Vec::<UTXOVar<C, CVar>>::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx_utxos.clone()),
            mode,
        )?;
        let shielded_tx_utxos_proofs = Vec::new_variable(
            cs.clone(),
            || Ok(user_aux.clone().shielded_tx_utxos_proofs),
            mode,
        )?;
        let openings_mask =
            Vec::new_variable(cs.clone(), || Ok(user_aux.openings_mask.clone()), mode)?;
        let shielded_tx_inclusion_proof = ShieldedTxInclusionProofVar::new_variable(
            cs.clone(),
            || Ok(user_aux.shielded_tx_inclusion_proof.clone()),
            mode,
        )?;
        let signer_pk_inclusion_proof = SignerInclusionProofVar::new_variable(
            cs.clone(),
            || Ok(user_aux.signer_pk_inclusion_proof.clone()),
            mode,
        )?;
        let pk = PublicKeyVar::new_variable(cs.clone(), || Ok(user_aux.pk), mode)?;
        Ok(UserAuxVar {
            block,
            shielded_tx,
            tx_index,
            shielded_tx_utxos,
            shielded_tx_utxos_proofs,
            openings_mask,
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof,
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
    pub fn update_balance<
        TC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // transaction tree config
        TCG: SparseConfigGadget<
            TC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = ShieldedTransactionVar<C, CVar>,
        >,
        SC: SparseConfig<InnerDigest = C::BaseField, TwoToOneHash = TwoToOneCRH<C::BaseField>>, // signer tree config
        SCG: SparseConfigGadget<
            SC,
            C::BaseField,
            InnerDigest = FpVar<C::BaseField>,
            TwoToOneHash = TwoToOneCRHGadget<C::BaseField>,
            LeafDigest = FpVar<C::BaseField>,
            Leaf = PublicKeyVar<C, CVar>,
        >,
    >(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        z_i: Vec<FpVar<C::BaseField>>,
        aux: UserAuxVar<C, CVar, TC, TCG, SC, SCG>,
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
                &self.pp, &aux.pk,
            )?;
        computed_pk_hash.enforce_equal(&pk_hash)?;

        // compute block hash and update accumulator value
        let next_block_hash = <BlockVarCRH<_, _, TCG, _, SCG> as CRHSchemeGadget<
            BlockCRH<_>,
            _,
        >>::evaluate(&self.pp, &aux.block)?;
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
        aux.shielded_tx_inclusion_proof
            .check_membership_with_index(
                &self.pp,
                &self.pp,
                &aux.block.tx_tree_root,
                &aux.shielded_tx,
                &next_tx_index,
            )?;

        // check that the signer bit is 1 for the corresponding transaction (i.e. pk is included)
        aux.signer_pk_inclusion_proof.check_membership(
            &self.pp,
            &self.pp,
            &aux.block.signer_tree_root,
            &aux.shielded_tx.from,
        )?;

        // validity of input utxos is already checked by the transaction validity circuit and the
        // aggregator, so we only need to process the output utxos?
        // note that the transaction validity circuit ensures that sum(inputs) == sum(outputs)
        let is_sender = aux.pk.key.is_eq(&aux.shielded_tx.from.key)?;
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
            let is_in_tree = utxo_proof.verify_membership(
                &self.pp,
                &self.pp,
                &aux.shielded_tx.shielded_tx,
                &utxo,
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
    use core::{
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
            crh::{poseidon_canonical_config, PublicKeyCRH},
        },
    };
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
    use ark_grumpkin::constraints::GVar as ProjectiveVar;
    use ark_grumpkin::Projective;
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        GR1CSVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{rand::RngCore, test_rng};

    use crate::UserAux;

    use super::{UserAuxVar, UserCircuit};

    pub fn make_signer_tree(
        pp: &PoseidonConfig<Fr>,
        users: &Vec<User<Projective>>,
    ) -> SignerTree<SignerTreeConfig<Projective>> {
        let mut signer_leaves = BTreeMap::new();
        for user in users {
            signer_leaves.insert(user.id as u64, user.keypair.pk);
        }
        SignerTree::<SignerTreeConfig<Projective>>::new(pp, pp, &signer_leaves).unwrap()
    }

    #[test]
    pub fn test_user_circuit() {
        let pp = poseidon_canonical_config::<Fr>();
        let mut rng = test_rng();
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

        let utxos = tx.inputs.clone().into_iter().chain(tx.outputs);

        let shielded_tx =
            MerkleTree::<ShieldedTransactionConfig<Projective>>::new(&pp, &pp, utxos.clone())
                .unwrap();

        let nullifiers = tx
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, utxo)| Nullifier::new(&pp, sender_sk, 0, idx, 0).unwrap())
            .collect::<Vec<_>>();

        let sender_transaction = ShieldedTransaction {
            from: sender.keypair.pk,
            shielded_tx: shielded_tx.root(),
        };

        let transactions = [
            ShieldedTransaction::default(),
            sender_transaction.clone(),
            ShieldedTransaction::default(),
            ShieldedTransaction::default(),
            ShieldedTransaction::default(),
        ];

        let tx_leaves = BTreeMap::from_iter(
            transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| (i as u64, tx.clone())),
        );
        let signer_tree = make_signer_tree(&pp, &vec![sender.clone()]);
        let transaction_tree = TransactionTree::new(&pp, &pp, &tx_leaves).unwrap();

        let block = Block {
            tx_tree_root: transaction_tree.root(),
            signer_tree_root: signer_tree.root(),
            nullifiers,
            signers: vec![Some(sender.id)],
            height: 1,
            deposits: vec![],
            withdrawals: vec![],
        };
        let shielded_tx_utxos_proofs = (4..8)
            .map(|idx| shielded_tx.generate_proof(idx).unwrap())
            .collect();
        let shielded_tx_inclusion_proof = transaction_tree.generate_membership_proof(1).unwrap();
        let signer_inclusion_proof = signer_tree.generate_membership_proof(0).unwrap();
        let sender_aux = UserAux {
            block,
            shielded_tx: sender_transaction,
            tx_index: Fr::ONE,
            shielded_tx_utxos: tx.outputs.to_vec(), // only outputs are processed
            shielded_tx_utxos_proofs,
            openings_mask: vec![true; 4],
            shielded_tx_inclusion_proof,
            signer_pk_inclusion_proof: signer_inclusion_proof,
            pk: sender.keypair.pk,
        };

        let cs = ConstraintSystem::new_ref();
        let sender_aux_var =
            UserAuxVar::<
                Projective,
                ProjectiveVar,
                TransactionTreeConfig<_>,
                TransactionTreeConfigGadget<_, _>,
                SignerTreeConfig<_>,
                SignerTreeConfigGadget<_, _>,
            >::new_variable(cs.clone(), || Ok(sender_aux), AllocationMode::Witness)
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
        >::new(pp_var.clone(), pp_var.clone());

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

use core::{
    datastructures::{
        block::constraints::BlockVar,
        keypair::constraints::PublicKeyVar,
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
    },
    primitives::{
        accumulator::constraints::Accumulator, sparsemt::constraints::MerkleSparseTreePathVar,
    },
    CommittedTransactionVar, ShieldedTransactionVar,
};
use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{poseidon::constraints::CRHParametersVar, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct UserCircuit<
    F: PrimeField + Absorb,
    C: CurveGroup,
    CVar: CurveVar<C, F>,
    H: TwoToOneCRHScheme,
    T: TwoToOneCRHSchemeGadget<H, F>,
    A: Accumulator<F, H, T>,
    const N_TX_PER_FOLD_STEP: usize,
> {
    _a: PhantomData<A>,
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
    acc_pp: T::ParametersVar, // public parameters for the accumulator might not be poseidon
    pp: CRHParametersVar<F>,
}

// client circuit
// 1. prove that the committed transaction is in the transaction tree
// 2. prove that user knows some opening of a utxo in this committed transaction
// 3. prove that signer bit of transaction originator has been set to 1
// 4. accordingly increase or decrease the user's balance
// 5.
//

#[derive(Clone, Debug)]
pub struct UserAuxVar<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>> {
    pub shielded_tx: ShieldedTransactionVar<C::BaseField>,
    pub committed_tx: CommittedTransactionVar<C::BaseField>,
    pub output_openings: Vec<FpVar<C::BaseField>>,
    pub committed_transaction_inclusion_proofs: F, // todo
    pub signer_pk_inclusion_proofs:
        Vec<MerkleSparseTreePathVar<SignerTreeConfig<C>, F, SignerTreeConfigGadget<C, CVar>>>,
    pub block: BlockVar<F>,
    pub pk: PublicKeyVar<C, CVar>,
}

impl<
        F: PrimeField + Absorb,
        C: CurveGroup<BaseField = F>,
        CVar: CurveVar<C, F>,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, F>,
        A: Accumulator<F, H, T>,
        const N_TX_PER_FOLD_STEP: usize,
    > UserCircuit<F, C, CVar, H, T, A, N_TX_PER_FOLD_STEP>
{
    pub fn update_balance(
        &self,
        cs: ConstraintSystemRef<F>,
        z_i: Vec<FpVar<F>>,
        aux: UserAuxVar<F, C, CVar>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        todo!()
    }
}

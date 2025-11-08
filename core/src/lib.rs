pub mod datastructures;
pub mod primitives;

use ark_crypto_primitives::{
    Error,
    crh::{
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
        poseidon::{
            CRH, TwoToOneCRH,
            constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget},
        },
    },
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::{
    CurveGroup,
    short_weierstrass::{Projective, SWCurveConfig},
};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_r1cs_std::{
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{CurveVar, curves::short_weierstrass::ProjectiveVar},
    uint64::UInt64,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::rand::Rng;

use crate::{
    datastructures::{
        keypair::constraints::PublicKeyVar,
        signerlist::{SignerTreeConfig, constraints::SignerTreeConfigGadget},
        utxo::{
            CommittedUTXOTreeConfig, UTXO,
            constraints::{CommittedUTXOTreeConfigGadget, UTXOVar},
        },
    },
    primitives::{
        crh::{UTXOCRH, constraints::UTXOVarCRH},
        sparsemt::constraints::MerkleSparseTreePathVar,
    },
};

const TX_TREE_HEIGHT: u64 = 13;
const SIGNER_TREE_HEIGHT: u64 = TX_TREE_HEIGHT;

type UserId = usize;

struct Nullifier<F> {
    value: F,
}

impl<F: PrimeField + Absorb> Nullifier<F> {
    fn new(cfg: &PoseidonConfig<F>, sk: F, i: usize, t: usize) -> Result<Self, Error> {
        Ok(Self {
            value: CRH::evaluate(cfg, [sk, F::from(i as u64), F::from(t as u64)])?,
        })
    }
}

struct NullifierVar<F: PrimeField> {
    value: FpVar<F>,
}

impl<F: PrimeField + Absorb> NullifierVar<F> {
    fn new(
        cfg: &CRHParametersVar<F>,
        sk: &FpVar<F>,
        i: &UInt64<F>,
        t: &UInt64<F>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            value: CRHGadget::evaluate(cfg, &[sk.clone(), i.to_fp()?, t.to_fp()?])?,
        })
    }
}

fn commit_utxo<C: CurveGroup<BaseField: PrimeField + Absorb>>(
    cfg: &PoseidonConfig<C::BaseField>,
    utxo: &UTXO<C>,
    mut rng: impl Rng,
) -> Result<(C::BaseField, C::BaseField), Error> {
    let r = C::BaseField::rand(&mut rng);
    let cm = TwoToOneCRH::evaluate(cfg, UTXOCRH::evaluate(cfg, utxo)?, r)?;

    Ok((cm, r))
}

fn commit_utxo_var<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
>(
    cfg: &CRHParametersVar<C::BaseField>,
    utxo: &UTXOVar<C, CVar>,
    r: &FpVar<C::BaseField>,
) -> Result<FpVar<C::BaseField>, SynthesisError> {
    TwoToOneCRHGadget::evaluate(cfg, &UTXOVarCRH::evaluate(cfg, utxo)?, r)
}

struct PlainTransaction<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    inputs: Vec<UTXO<C>>,
    outputs: Vec<UTXO<C>>,
}

struct ShieldedTransaction<F: Field> {
    inputs: Vec<Nullifier<F>>,
    outputs: Vec<F>,
}

struct PlainTransactionVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    inputs: Vec<UTXOVar<C, CVar>>,
    outputs: Vec<UTXOVar<C, CVar>>,
}

struct ShieldedTransactionVar<F: PrimeField> {
    inputs: Vec<NullifierVar<F>>,
    outputs: Vec<FpVar<F>>,
}

fn tx_validity<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>(
    cfg: &CRHParametersVar<C::BaseField>,
    sk: &FpVar<C::BaseField>, // TODO: sk and pk no longer being EC

    plain_tx: &PlainTransactionVar<C, CVar>,
    shielded_tx: &ShieldedTransactionVar<C::BaseField>,
    input_openings: &[FpVar<C::BaseField>],
    output_openings: &[FpVar<C::BaseField>],

    utxo_tree_root: &FpVar<C::BaseField>,
    signer_tree_root: &FpVar<C::BaseField>,
    utxo_indexes: &[UInt64<C::BaseField>],
    signer_indexes: &[UInt64<C::BaseField>],
    utxo_paths: &[MerkleSparseTreePathVar<
        CommittedUTXOTreeConfig<C::BaseField>,
        C::BaseField,
        CommittedUTXOTreeConfigGadget<C::BaseField>,
    >],
    signer_paths: &[MerkleSparseTreePathVar<
        SignerTreeConfig<C>,
        C::BaseField,
        SignerTreeConfigGadget<C, CVar>,
    >],
    sender_pks: &[PublicKeyVar<C, CVar>],

    block_tree_root: &FpVar<C::BaseField>,
    block_index: &UInt64<C::BaseField>,
) -> Result<(), SynthesisError> {
    // TODO: filter dummy UTXOs
    for (nullifier, utxo_idx) in shielded_tx.inputs.iter().zip(utxo_indexes) {
        NullifierVar::new(cfg, sk, utxo_idx, block_index)?
            .value
            .enforce_equal(&nullifier.value)?;
    }
    // TODO: check sk and pk match

    for ((utxo, cm), r) in plain_tx
        .outputs
        .iter()
        .zip(&shielded_tx.outputs)
        .zip(output_openings)
    {
        commit_utxo_var(cfg, utxo, r)?.enforce_equal(cm)?;
    }

    plain_tx
        .inputs
        .iter()
        .map(|i| &i.amount)
        .sum::<FpVar<C::BaseField>>()
        .enforce_equal(
            &plain_tx
                .inputs
                .iter()
                .map(|i| &i.amount)
                .sum::<FpVar<C::BaseField>>(),
        )?;

    for ((((((utxo, r), utxo_idx), signer_idx), utxo_path), signer_path), sender_pk) in plain_tx
        .inputs
        .iter()
        .zip(input_openings)
        .zip(utxo_indexes)
        .zip(signer_indexes)
        .zip(utxo_paths)
        .zip(signer_paths)
        .zip(sender_pks)
    {
        let cm = commit_utxo_var(cfg, utxo, r)?;
        utxo_path.check_membership_with_index(
            cfg,
            cfg,
            utxo_tree_root,
            &(cm, signer_idx.clone()),
            utxo_idx,
        )?;
        signer_path.check_membership_with_index(
            cfg,
            cfg,
            signer_tree_root,
            &sender_pk,
            signer_idx,
        )?;
    }

    todo!();
    Ok(())
}

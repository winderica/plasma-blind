use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use plasmablind_core::{
    config::PlasmaBlindConfigVar,
    datastructures::{signerlist::SIGNER_TREE_ARITY, txtree::TRANSACTION_TREE_ARITY},
};
use sonobe_primitives::{algebra::ops::bits::ToBitsGadgetExt, transcripts::Absorbable};
use std::{cmp::Ordering, marker::PhantomData};

pub mod balance_inputs;
pub mod balance_state;
pub mod circuit;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMaskVar<F> = Vec<Boolean<F>>;

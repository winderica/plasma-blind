use std::{iter::Map, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;

use super::user::UserId;
use crate::primitives::{
    sparsemt::{MerkleSparseTree, SparseConfig},
};

pub mod constraints;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Nonce(pub u64);

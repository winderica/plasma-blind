use ark_crypto_primitives::{
    merkle_tree::{Config, Path},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::UTXO;
use crate::{
    SIGNER_TREE_HEIGHT, TX_TREE_HEIGHT, datastructures::{
        block::{Block, BlockMetadata}, blocktree::{BLOCK_TREE_HEIGHT, BlockTreeConfig}, keypair::PublicKey, nullifier::Nullifier, shieldedtx::{SHIELDED_TX_TREE_HEIGHT, ShieldedTransaction, ShieldedTransactionConfig}
    }, primitives::sparsemt::SparseConfig
};

pub mod constraints;

// each input utxo requires a proof, attesting to its validity and nullifier
// valid utxo = included in shielded tx, within a tx tree which was signed at a certain block
// included within the block tree
#[derive(Clone)]
pub struct UTXOProof<F> {
    block: BlockMetadata<F>,
    utxo_path: Vec<F>,
    signer_path: Vec<F>,
    tx_path: Vec<F>,
    block_path: Vec<F>,
}

impl<F: PrimeField> UTXOProof<F> {
    pub fn new(
        block: BlockMetadata<F>,
        utxo_inclusion_proof: Vec<F>,
        signer_inclusion_proof: Vec<F>,
        tx_inclusion_proof: Vec<F>,
        block_inclusion_proof: Vec<F>,
    ) -> Self {
        UTXOProof {
            block,
            utxo_path: utxo_inclusion_proof,
            signer_path: signer_inclusion_proof,
            tx_path: tx_inclusion_proof,
            block_path: block_inclusion_proof,
        }
    }
}

impl<F: PrimeField> Default for UTXOProof<F> {
    fn default() -> Self {
        Self {
            block: Default::default(),
            utxo_path: vec![Default::default(); SHIELDED_TX_TREE_HEIGHT - 1],
            signer_path: vec![Default::default(); SIGNER_TREE_HEIGHT - 1],
            tx_path: vec![Default::default(); TX_TREE_HEIGHT - 1],
            block_path: vec![Default::default(); BLOCK_TREE_HEIGHT - 1],
        }
    }
}

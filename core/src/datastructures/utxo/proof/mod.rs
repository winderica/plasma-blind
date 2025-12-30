use ark_crypto_primitives::{
    merkle_tree::{Config, Path},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use nmerkle_trees::sparse::NArySparsePath;

use super::UTXO;
use crate::{
    SIGNER_TREE_HEIGHT, TX_TREE_HEIGHT,
    datastructures::{
        block::{Block, BlockMetadata},
        blocktree::{
            BLOCK_TREE_ARITY, BLOCK_TREE_HEIGHT, BlockTreeConfig, SparseNAryBlockTree,
            SparseNAryBlockTreeConfig,
        },
        keypair::PublicKey,
        nullifier::Nullifier,
        shieldedtx::{SHIELDED_TX_TREE_HEIGHT, ShieldedTransaction, ShieldedTransactionConfig},
    },
    primitives::sparsemt::SparseConfig,
};

pub mod constraints;

// each input utxo requires a proof, attesting to its validity and nullifier
// valid utxo = included in shielded tx, within a tx tree which was signed at a certain block
// included within the block tree
#[derive(Clone)]
pub struct UTXOProof<F: PrimeField + Absorb> {
    pub block: BlockMetadata<F>,
    pub utxo_path: Vec<F>,
    pub signer_path: Vec<F>,
    pub tx_path: Vec<F>,
    pub block_path:
        NArySparsePath<BLOCK_TREE_ARITY, BlockTreeConfig<F>, SparseNAryBlockTreeConfig<F>>,
}

impl<F: PrimeField + Absorb> UTXOProof<F> {
    pub fn new(
        block: BlockMetadata<F>,
        utxo_inclusion_proof: Vec<F>,
        signer_inclusion_proof: Vec<F>,
        tx_inclusion_proof: Vec<F>,
        block_inclusion_proof: NArySparsePath<
            BLOCK_TREE_ARITY,
            BlockTreeConfig<F>,
            SparseNAryBlockTreeConfig<F>,
        >,
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

impl<F: PrimeField + Absorb> Default for UTXOProof<F> {
    fn default() -> Self {
        Self {
            block: Default::default(),
            utxo_path: vec![Default::default(); SHIELDED_TX_TREE_HEIGHT - 1],
            signer_path: vec![Default::default(); SIGNER_TREE_HEIGHT - 1],
            tx_path: vec![Default::default(); TX_TREE_HEIGHT - 1],
            block_path: Default::default(),
        }
    }
}

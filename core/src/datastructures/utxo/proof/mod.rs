use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use nmerkle_trees::sparse::NArySparsePath;

use crate::datastructures::{
    block::BlockMetadata,
    blocktree::{BLOCK_TREE_ARITY, BlockTreeConfig, SparseNAryBlockTreeConfig},
    shieldedtx::SHIELDED_TX_TREE_HEIGHT,
    signerlist::{SIGNER_TREE_ARITY, SignerTreeConfig, SparseNArySignerTreeConfig},
    txtree::{SparseNAryTransactionTreeConfig, TRANSACTION_TREE_ARITY, TransactionTreeConfig},
};

pub mod constraints;

// each input utxo requires a proof, attesting to its validity and nullifier
// valid utxo = included in shielded tx, within a tx tree which was signed at a certain block
// included within the block tree
#[derive(Clone)]
pub struct UTXOProof<F: PrimeField + Absorb> {
    pub block: BlockMetadata<F>,
    pub utxo_path: Vec<F>,
    pub signer_path:
        NArySparsePath<SIGNER_TREE_ARITY, SignerTreeConfig<F>, SparseNArySignerTreeConfig<F>>,
    pub tx_path: NArySparsePath<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<F>,
        SparseNAryTransactionTreeConfig<F>,
    >,
    pub block_path:
        NArySparsePath<BLOCK_TREE_ARITY, BlockTreeConfig<F>, SparseNAryBlockTreeConfig<F>>,
}

impl<F: PrimeField + Absorb> UTXOProof<F> {
    pub fn new(
        block: BlockMetadata<F>,
        utxo_inclusion_proof: Vec<F>,
        signer_inclusion_proof: NArySparsePath<
            SIGNER_TREE_ARITY,
            SignerTreeConfig<F>,
            SparseNArySignerTreeConfig<F>,
        >,
        tx_inclusion_proof: NArySparsePath<
            TRANSACTION_TREE_ARITY,
            TransactionTreeConfig<F>,
            SparseNAryTransactionTreeConfig<F>,
        >,
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
            signer_path: Default::default(),
            tx_path: Default::default(),
            block_path: Default::default(),
        }
    }
}

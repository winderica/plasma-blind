use nmerkle_trees::sparse::NArySparsePath;
use plasmablind_core::datastructures::{
    block::BlockMetadata,
    blocktree::BLOCK_TREE_ARITY,
    signerlist::{SignerTreeConfig, SparseNArySignerTreeConfig},
    txtree::{SparseNAryTransactionTreeConfig, TransactionTreeConfig, TRANSACTION_TREE_ARITY},
    utxo::UTXO,
};

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use sonobe_primitives::transcripts::Absorbable;

pub mod circuits;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMask = Vec<bool>;

pub struct UserAux<F: PrimeField + Absorb + Absorbable> {
    pub block: BlockMetadata<F>,
    pub from: F,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub utxo_tree_root: F,
    // index of transaction within transaction tree
    pub tx_index: F,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXO<F>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<(Vec<F>, F)>,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: Vec<bool>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof: NArySparsePath<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<F>,
        SparseNAryTransactionTreeConfig<F>,
    >,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof:
        NArySparsePath<BLOCK_TREE_ARITY, SignerTreeConfig<F>, SparseNArySignerTreeConfig<F>>,
}

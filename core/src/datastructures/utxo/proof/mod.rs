use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use nmerkle_trees::sparse::NArySparsePath;
use sonobe_primitives::transcripts::Absorbable;

use crate::{datastructures::{
    block::BlockMetadata,
    blocktree::{BLOCK_TREE_ARITY, BlockTreeConfig, SparseNAryBlockTreeConfig},
    shieldedtx::SHIELDED_TX_TREE_HEIGHT,
    signerlist::{SIGNER_TREE_ARITY, SignerTreeConfig, SparseNArySignerTreeConfig},
    txtree::{SparseNAryTransactionTreeConfig, TRANSACTION_TREE_ARITY, TransactionTreeConfig},
}, primitives::crh::utils::Init};

pub mod constraints;

// each input utxo requires a proof, attesting to its validity and nullifier
// valid utxo = included in shielded tx, within a tx tree which was signed at a certain block
// included within the block tree
#[derive(Clone)]
pub struct UTXOProof<Cfg: Init> {
    pub block: BlockMetadata<Cfg::F>,
    pub utxo_path: Vec<Cfg::F>,
    pub signer_path:
        NArySparsePath<SIGNER_TREE_ARITY, SignerTreeConfig<Cfg>, SparseNArySignerTreeConfig<Cfg>>,
    pub tx_path: NArySparsePath<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<Cfg>,
        SparseNAryTransactionTreeConfig<Cfg>,
    >,
    pub block_path:
        NArySparsePath<BLOCK_TREE_ARITY, BlockTreeConfig<Cfg>, SparseNAryBlockTreeConfig<Cfg>>,
}

impl<Cfg: Init> UTXOProof<Cfg> {
    pub fn new(
        block: BlockMetadata<Cfg::F>,
        utxo_inclusion_proof: Vec<Cfg::F>,
        signer_inclusion_proof: NArySparsePath<
            SIGNER_TREE_ARITY,
            SignerTreeConfig<Cfg>,
            SparseNArySignerTreeConfig<Cfg>,
        >,
        tx_inclusion_proof: NArySparsePath<
            TRANSACTION_TREE_ARITY,
            TransactionTreeConfig<Cfg>,
            SparseNAryTransactionTreeConfig<Cfg>,
        >,
        block_inclusion_proof: NArySparsePath<
            BLOCK_TREE_ARITY,
            BlockTreeConfig<Cfg>,
            SparseNAryBlockTreeConfig<Cfg>,
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

impl<Cfg: Init> Default for UTXOProof<Cfg> {
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

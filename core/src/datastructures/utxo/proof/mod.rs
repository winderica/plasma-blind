use ark_crypto_primitives::{
    merkle_tree::{Config, Path},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::UTXO;
use crate::{
    SIGNER_TREE_HEIGHT, TX_TREE_HEIGHT, datastructures::{
        block::Block, blocktree::{BLOCK_TREE_HEIGHT, BlockTreeConfig}, keypair::PublicKey, nullifier::Nullifier, shieldedtx::{SHIELDED_TX_TREE_HEIGHT, ShieldedTransaction, ShieldedTransactionConfig}
    }, primitives::sparsemt::SparseConfig
};

pub mod constraints;

// each input utxo requires a proof, attesting to its validity and nullifier
// valid utxo = included in shielded tx, within a tx tree which was signed at a certain block
// included within the block tree
#[derive(Clone)]
pub struct UTXOProof<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    block: Block<C::BaseField>,
    signer: PublicKey<C>,
    utxo_tree_root: C::BaseField,
    tx_index: C::BaseField,
    utxo_index: C::BaseField,
    utxo_path: Vec<C::BaseField>,
    signer_path: Vec<C::BaseField>,
    signer_index: C::BaseField,
    tx_path: Vec<C::BaseField>,
    block_tree_root: C::BaseField,
    block_path: Vec<C::BaseField>,
    block_index: C::BaseField,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> UTXOProof<C> {
    pub fn new(
        block: Block<C::BaseField>,
        signer: PublicKey<C>,
        utxo_tree_root: C::BaseField,
        tx_index: C::BaseField,
        utxo_index: C::BaseField,
        utxo_inclusion_proof: Vec<C::BaseField>,
        signer_inclusion_proof: Vec<C::BaseField>,
        signer_index: C::BaseField,
        tx_inclusion_proof: Vec<C::BaseField>,
        block_tree_root: C::BaseField,
        block_inclusion_proof: Vec<C::BaseField>,
        block_index: C::BaseField,
    ) -> Self {
        UTXOProof {
            block,
            signer,
            utxo_tree_root,
            tx_index,
            utxo_index,
            utxo_path: utxo_inclusion_proof,
            signer_path: signer_inclusion_proof,
            signer_index,
            tx_path: tx_inclusion_proof,
            block_tree_root,
            block_path: block_inclusion_proof,
            block_index,
        }
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Default for UTXOProof<C> {
    fn default() -> Self {
        Self {
            block: Default::default(),
            signer: Default::default(),
            utxo_tree_root: Default::default(),
            tx_index: Default::default(),
            utxo_index: Default::default(),
            utxo_path: vec![Default::default(); SHIELDED_TX_TREE_HEIGHT - 1],
            signer_path: vec![Default::default(); SIGNER_TREE_HEIGHT - 1],
            signer_index: Default::default(),
            tx_path: vec![Default::default(); TX_TREE_HEIGHT - 1],
            block_tree_root: Default::default(),
            block_path: vec![Default::default(); BLOCK_TREE_HEIGHT - 1],
            block_index: Default::default(),
        }
    }
}

use plasmablind_core::datastructures::{
    block::{Block, BlockMetadata},
    keypair::PublicKey,
    shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
    signerlist::SignerTreeConfig,
    txtree::TransactionTreeConfig,
    utxo::UTXO,
};

use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

pub mod circuits;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMask = Vec<bool>;

#[derive(Clone, Debug)]
pub struct UserAux<F: PrimeField + Absorb> {
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
    pub shielded_tx_inclusion_proof: Vec<F>,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof: Vec<F>,
}

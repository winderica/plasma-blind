use core::{
    datastructures::{
        block::Block,
        keypair::PublicKey,
        shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
        signerlist::SignerTreeConfig,
        txtree::TransactionTreeConfig,
        utxo::UTXO,
    },
    primitives::sparsemt::MerkleSparseTreePath,
};

use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

pub mod circuits;

// indicates which utxo will be processed by balance circuit
pub type OpeningsMask = Vec<bool>;
pub type ShieldedTxInclusionProof<C> = MerkleSparseTreePath<TransactionTreeConfig<C>>;
pub type SignerInclusionProof<C> = MerkleSparseTreePath<SignerTreeConfig<C>>;

#[derive(Clone, Debug)]
pub struct UserAux<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    pub block: Block<C::BaseField>,
    // shielded tx is the root of the shielded tx tree along its index in the transaction tree which was built by the aggregator
    pub shielded_tx: ShieldedTransaction<C>,
    // index of transaction within transaction tree
    pub tx_index: C::BaseField,
    // output utxos only from shielded tx
    pub shielded_tx_utxos: Vec<UTXO<C>>,
    // openings for utxos
    pub shielded_tx_utxos_proofs: Vec<Path<ShieldedTransactionConfig<C>>>,
    // openings mask - indicates if utxo should be opened. should be filled with true when user is sender.
    pub openings_mask: Vec<bool>,
    // inclusion proof showing committed_tx was included in tx tree
    pub shielded_tx_inclusion_proof: ShieldedTxInclusionProof<C>,
    // inclusion proof showing committed_tx was signed
    pub signer_pk_inclusion_proof: SignerInclusionProof<C>,
    pub pk: PublicKey<C>,
}

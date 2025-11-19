use crate::Nullifier;

pub mod constraints;

pub type BlockHash<F> = F;

// contains the roots of utxo, transaction, signer, deposit and withdraw trees
#[derive(Clone, Default, Debug)]
pub struct Block<F> {
    pub tx_tree_root: F,
    pub signer_tree_root: F,
    pub nullifiers: Vec<Nullifier<F>>,
    // the list of signer ids
    pub signers: Vec<Option<u32>>,
    pub height: usize,
    pub deposits: Vec<(u32, u64)>,
    pub withdrawals: Vec<(u32, u64)>,
}

use ark_crypto_primitives::{
    merkle_tree::{Config, Path},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::{
    datastructures::{
        block::Block,
        blocktree::BlockTreeConfig,
        nullifier::Nullifier,
        shieldedtx::{ShieldedTransaction, ShieldedTransactionConfig},
    },
    primitives::sparsemt::{MerkleSparseTreePath, SparseConfig},
};

use super::UTXO;

pub mod constraints;

// each input utxo requires a proof, attesting to its validity and nullifier
// valid utxo = included in shielded tx, within a tx tree which was signed at a certain block
// included within the block tree
#[derive(Default, Clone)]
pub struct UTXOProof<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    TC: SparseConfig,
    SC: SparseConfig,
> {
    block: Block<C::BaseField>,
    tx: ShieldedTransaction<C>,
    tx_index: C::BaseField,
    utxo: UTXO<C>,
    utxo_index: C::BaseField,
    utxo_inclusion_proof: Path<ShieldedTransactionConfig<C>>,
    signer_inclusion_proof: MerkleSparseTreePath<SC>,
    tx_inclusion_proof: MerkleSparseTreePath<TC>,
    block_tree_root: <BlockTreeConfig<C> as Config>::InnerDigest,
    block_inclusion_proof: MerkleSparseTreePath<BlockTreeConfig<C>>,
    nullifier: Nullifier<C::BaseField>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, TC: SparseConfig, SC: SparseConfig>
    UTXOProof<C, TC, SC>
{
    pub fn new(
        block: Block<C::BaseField>,
        tx: ShieldedTransaction<C>,
        tx_index: C::BaseField,
        utxo: UTXO<C>,
        utxo_index: C::BaseField,
        utxo_inclusion_proof: Path<ShieldedTransactionConfig<C>>,
        signer_inclusion_proof: MerkleSparseTreePath<SC>,
        tx_inclusion_proof: MerkleSparseTreePath<TC>,
        block_tree_root: <BlockTreeConfig<C> as Config>::InnerDigest,
        block_inclusion_proof: MerkleSparseTreePath<BlockTreeConfig<C>>,
        nullifier: Nullifier<C::BaseField>,
    ) -> Self {
        UTXOProof {
            block,
            tx,
            tx_index,
            utxo,
            utxo_index,
            utxo_inclusion_proof,
            signer_inclusion_proof,
            tx_inclusion_proof,
            block_tree_root,
            block_inclusion_proof,
            nullifier,
        }
    }
}

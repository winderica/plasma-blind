use ark_ec::CurveGroup;

use super::{TX_IO_SIZE, utxo::UTXO};

pub mod constraints;

#[derive(Clone, Debug)]
pub struct TransparentTransaction<C: CurveGroup> {
    pub inputs: [UTXO<C>; TX_IO_SIZE],
    pub outputs: [UTXO<C>; TX_IO_SIZE],
}

impl<C: CurveGroup> TransparentTransaction<C> {
    pub fn new(inputs: [UTXO<C>; TX_IO_SIZE], outputs: [UTXO<C>; TX_IO_SIZE]) -> Self {
        Self { inputs, outputs }
    }
}

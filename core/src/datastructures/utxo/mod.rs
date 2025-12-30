use std::fmt::Debug;




pub mod constraints;
pub mod proof;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct UTXO<F> {
    pub amount: u64,
    pub pk: F,
    pub salt: F,
    pub is_dummy: bool,
}

#[derive(Clone, Debug, Default, Copy, Eq, PartialEq, Hash)]
pub struct UTXOInfo<F> {
    pub from: F,
    pub utxo_index: usize,
    pub tx_index: usize,
    pub block_height: usize,
}

impl<F: Debug> Debug for UTXO<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_dummy {
            write!(f, "UTXO(dummy)")
        } else {
            write!(f, "UTXO({:?}, {})", self.pk, self.amount)
        }
    }
}

impl<F: Default> UTXO<F> {
    pub fn new(pk: F, amount: u64, salt: F) -> Self {
        UTXO {
            amount,
            pk,
            salt,
            is_dummy: false,
        }
    }

    pub fn dummy() -> Self {
        UTXO {
            amount: 0,
            pk: F::default(),
            salt: F::default(),
            is_dummy: true,
        }
    }
}

impl<F: Default> Default for UTXO<F> {
    fn default() -> Self {
        UTXO::dummy()
    }
}

pub mod block;
pub mod blocktree;
pub mod deposits;
pub mod keypair;
pub mod noncemap;
pub mod nullifier;
pub mod publickeymap;
pub mod shieldedtx;
pub mod signerlist;
pub mod transparenttx;
pub mod txtree;
pub mod user;
pub mod utxo;
pub mod withdrawals;

// max number of input/output utxos in a transaction
// |tx_inputs| + |tx_outputs| == TX_IO_SIZE * 2
pub const TX_IO_SIZE: usize = match option_env!("TX_IO_SIZE") {
    Some(s) => {
        // const-compatible string-to-usize parsing
        let bytes = s.as_bytes();
        let mut result: usize = 0;
        let mut i = 0;
        while i < bytes.len() {
            result = result * 10 + (bytes[i] - b'0') as usize;
            i += 1;
        }
        result
    }
    None => 2, // should be a power of 2
};

pub const USER_ID_ROLLUP: usize = 0;

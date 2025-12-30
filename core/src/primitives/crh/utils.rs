use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_ff::PrimeField;

// WARNING: this config should be checked and not used in production as is
pub fn initialize_two_to_one_binary_tree_poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    // eprint 2019/458, p.8, for trees of arity = 2 at 128 bits of security
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 5; // fixed, don't use -1 or 3
    let rate = 2; // rate is at 2 for binary tree
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

// WARNING: this config should be checked and not used in production as is
pub fn initialize_utxocrh_config<F: PrimeField>() -> PoseidonConfig<F> {
    let rate = 4;
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5; // fixed
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

// WARNING: this config should be checked and not used in production as is
pub fn initialize_shieldedtransactioncrh_config<F: PrimeField>() -> PoseidonConfig<F> {
    let rate = 2;
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 5; // fixed
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

// WARNING: this config should be checked and not used in production as is
pub fn initialize_publickeycrh_config<F: PrimeField>() -> PoseidonConfig<F> {
    let rate = 3;
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5; // fixed
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

// WARNING: this config should be checked and not used in production as is
pub fn initialize_blockcrh_config<F: PrimeField>() -> PoseidonConfig<F> {
    let rate = 3;
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5; // fixed
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

// WARNING: this config should be checked and not used in production as is
pub fn initialize_poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5; // fixed
    let rate = 4;
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

// WARNING: this config should be checked and not used in production as is
pub fn initialize_n_to_one_config<const N: usize, F: PrimeField>() -> PoseidonConfig<F> {
    let rate = N;
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5; // fixed
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

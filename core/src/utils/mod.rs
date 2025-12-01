use ark_ff::PrimeField;
use ark_relations::gr1cs::Matrix;
use ark_std::cfg_iter;

use crate::errs::PlasmaBlindError;

pub fn hadamard<F: PrimeField>(a: &[F], b: &[F]) -> Result<Vec<F>, PlasmaBlindError> {
    Ok(cfg_iter!(a).zip(b).map(|(a, b)| *a * b).collect())
}

pub fn vec_sub<F: PrimeField>(a: &[F], b: &[F]) -> Result<Vec<F>, PlasmaBlindError> {
    Ok(cfg_iter!(a).zip(b).map(|(x, y)| *x - y).collect())
}

pub fn is_zero_vec<F: PrimeField>(vec: &[F]) -> bool {
    cfg_iter!(vec).all(|a| a.is_zero())
}

pub fn mat_vec_mul<F: PrimeField>(m: &Matrix<F>, z: &[F]) -> Result<Vec<F>, PlasmaBlindError> {
    Ok(cfg_iter!(m)
        .map(|row| row.iter().map(|(value, col_i)| *value * z[*col_i]).sum())
        .collect())
}

pub fn vec_scalar_mul<F: PrimeField>(vec: &[F], c: &F) -> Vec<F> {
    cfg_iter!(vec).map(|a| *a * c).collect()
}

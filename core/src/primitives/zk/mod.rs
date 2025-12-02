// re-using some utilities from https://github.com/privacy-ethereum/sonobe/blob/main/folding-schemes/src/utils/vec.rs
use crate::{
    errs::PlasmaBlindError,
    utils::{hadamard, vec_scalar_mul, vec_sub},
};
use ark_ff::PrimeField;
use ark_relations::gr1cs::{Matrix, mat_vec_mul};
use ark_std::rand::RngCore;
use sonobe_primitives::commitments::VectorCommitmentOps;

// implement relaxed r1cs sampling
// see eprint 2023/573, construction 5
pub fn sample_rr1cs<F: PrimeField, VC: VectorCommitmentOps<Scalar = F>>(
    a: &Matrix<F>,
    b: &Matrix<F>,
    c: &Matrix<F>,
    w_len: usize,
    x_len: usize,
    ck: VC::Key, // commitment key
    rng: &mut impl RngCore,
) -> Result<(), PlasmaBlindError> {
    let w = (0..w_len).map(|_| F::rand(rng)).collect::<Vec<_>>();
    //let (w_bar, rw) = VC::commit(&ck, &w, rng)?;
    //let x = (0..x_len).map(|_| F::rand(rng)).collect::<Vec<_>>();
    //let u = x[0];
    //let z = [x, w].concat();

    //let azbz = hadamard(&mat_vec_mul(a, &z), &mat_vec_mul(b, &z))?;
    //let ucz = vec_scalar_mul(&mat_vec_mul(c, &z), &u);

    //let e = vec_sub(&azbz, &ucz)?;
    //let (e_bar, re) = VC::commit(&ck, &e, rng)?;
    todo!();
    Ok(())
}

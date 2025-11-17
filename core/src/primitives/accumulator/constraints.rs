use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
        poseidon::{
            TwoToOneCRH,
            constraints::{CRHParametersVar, TwoToOneCRHGadget},
        },
    },
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

pub trait Accumulator<F: PrimeField, H: TwoToOneCRHScheme, T: TwoToOneCRHSchemeGadget<H, F>> {
    fn update(
        pp: &T::ParametersVar,
        prev: &FpVar<F>,
        value: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError>;
}

pub struct PoseidonAccumulatorVar<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Accumulator<F, TwoToOneCRH<F>, TwoToOneCRHGadget<F>>
    for PoseidonAccumulatorVar<F>
{
    fn update(
        pp: &CRHParametersVar<F>,
        prev: &FpVar<F>,
        value: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        TwoToOneCRHGadget::evaluate(pp, prev, value)
    }
}

use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
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

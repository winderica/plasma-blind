use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget, TwoToOneCRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sonobe_primitives::transcripts::{
    Absorbable,
    griffin::{constraints::crh::GriffinParamsVar, sponge::GriffinSpongeVar},
};

use super::{BlockTreeCRH, PublicKeyCRH, UTXOCRH};
use crate::{
    datastructures::{
        block::constraints::BlockMetadataVar, keypair::constraints::PublicKeyVar,
        noncemap::constraints::NonceVar, nullifier::constraints::NullifierVar,
        utxo::constraints::UTXOVar,
    },
    primitives::crh::{IdentityCRH, IntervalCRH, NTo1CRH, NullifierCRH, utils::Init},
};

pub struct IdentityCRHGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<IdentityCRH<F>, F> for IdentityCRHGadget<F> {
    type InputVar = FpVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = ();

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Ok(input.clone())
    }
}

pub struct IntervalCRHGadget<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize>
    CRHSchemeGadget<IntervalCRH<Cfg>, Cfg::F> for IntervalCRHGadget<Cfg>
{
    type InputVar = (FpVar<Cfg::F>, FpVar<Cfg::F>);
    type OutputVar = FpVar<Cfg::F>;
    type ParametersVar = Cfg::Var;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Cfg::HGadget::evaluate(parameters, &[input.0.clone(), input.1.clone()])
    }
}

pub struct PublicKeyVarCRH<
    Cfg,
    C: CurveGroup<BaseField: PrimeField>,
    CVar: CurveVar<C, C::BaseField>,
> {
    _c: PhantomData<(Cfg, C, CVar)>,
}

impl<
    Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize,
    C: CurveGroup<BaseField = Cfg::F>,
    CVar: CurveVar<C, C::BaseField>,
> CRHSchemeGadget<PublicKeyCRH<Cfg, C>, C::BaseField> for PublicKeyVarCRH<Cfg, C, CVar>
{
    type InputVar = PublicKeyVar<C, CVar>;
    type OutputVar = FpVar<C::BaseField>;
    type ParametersVar = Cfg::Var;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        let key = input.key.to_constraint_field()?;
        Cfg::HGadget::evaluate(parameters, &key)
    }
}

#[derive(Default)]
pub struct UTXOVarCRH<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize>
    CRHSchemeGadget<UTXOCRH<Cfg>, Cfg::F> for UTXOVarCRH<Cfg>
{
    type InputVar = UTXOVar<Cfg::F>;
    type OutputVar = FpVar<Cfg::F>;
    type ParametersVar = Cfg::Var;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        let bool_as_fp = input.is_dummy.clone().into();
        let pk_point = input.pk.clone();
        let input = Vec::from([
            input.amount.to_fp()?,
            bool_as_fp,
            input.salt.clone(),
            pk_point,
        ]);
        Cfg::HGadget::evaluate(parameters, &input)
    }
}

pub struct NullifierVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<NullifierCRH<F>, F> for NullifierVarCRH<F> {
    type InputVar = NullifierVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = ();

    fn evaluate(
        _parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Ok(input.value.clone())
    }
}

pub struct BlockTreeVarCRH<Cfg> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Clone + Init + CanonicalSerialize + CanonicalDeserialize>
    CRHSchemeGadget<BlockTreeCRH<Cfg>, Cfg::F> for BlockTreeVarCRH<Cfg>
{
    type InputVar = BlockMetadataVar<Cfg::F>;
    type OutputVar = FpVar<Cfg::F>;
    type ParametersVar = Cfg::Var;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Cfg::HGadget::evaluate(
            parameters,
            &[
                input.tx_tree_root.clone(),
                input.signer_tree_root.clone(),
                input.nullifier_tree_root.clone(),
                input.height.to_fp()?,
            ],
        )
    }
}

pub struct NTo1CRHVar<Cfg, const N: usize> {
    _f: PhantomData<Cfg>,
}

impl<Cfg: Init, const N: usize> CRHSchemeGadget<NTo1CRH<Cfg, N>, Cfg::F> for NTo1CRHVar<Cfg, N> {
    type InputVar = [FpVar<Cfg::F>];
    type OutputVar = FpVar<Cfg::F>;
    type ParametersVar = Cfg::Var;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Cfg::HGadget::evaluate(parameters, &input)
    }
}

impl<Cfg: Init> TwoToOneCRHSchemeGadget<NTo1CRH<Cfg, 2>, Cfg::F> for NTo1CRHVar<Cfg, 2> {
    type InputVar = FpVar<Cfg::F>;

    type OutputVar = FpVar<Cfg::F>;

    type ParametersVar = Cfg::Var;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Cfg::HGadget::evaluate(parameters, &[left_input.clone(), right_input.clone()])
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Cfg::HGadget::evaluate(parameters, &[left_input.clone(), right_input.clone()])
    }
}

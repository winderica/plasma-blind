use sonobe_primitives::transcripts::griffin::constraints::crh::GriffinParamsVar;
use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};
use sonobe_primitives::transcripts::{Absorbable, griffin::sponge::GriffinSpongeVar};

use super::{BlockTreeCRH, BlockTreeCRHGriffin, NonceCRH, PublicKeyCRH, UTXOCRH};
use crate::{
    datastructures::{
        block::constraints::BlockMetadataVar, keypair::constraints::PublicKeyVar,
        noncemap::constraints::NonceVar, nullifier::constraints::NullifierVar,
        utxo::constraints::UTXOVar,
    },
    primitives::crh::{IdentityCRH, IntervalCRH, NullifierCRH},
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

pub struct IntervalCRHGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<IntervalCRH<F>, F> for IntervalCRHGadget<F> {
    type InputVar = (FpVar<F>, FpVar<F>);
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        CRHGadget::evaluate(parameters, &[input.0.clone(), input.1.clone()])
    }
}

pub struct ShieldedTransactionVarCRH<C, CVar> {
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

pub struct NonceVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<NonceCRH<F>, F> for NonceVarCRH<F> {
    type InputVar = NonceVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        CRHGadget::evaluate(parameters, [input.to_fp()?].as_slice())
    }
}

pub struct PublicKeyVarCRH<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    _c: PhantomData<C>,
    _c1: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    CRHSchemeGadget<PublicKeyCRH<C>, C::BaseField> for PublicKeyVarCRH<C, CVar>
{
    type InputVar = PublicKeyVar<C, CVar>;
    type OutputVar = FpVar<C::BaseField>;
    type ParametersVar = CRHParametersVar<C::BaseField>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        let key = input.key.to_constraint_field()?;
        CRHGadget::evaluate(parameters, &key)
    }
}

#[derive(Default)]
pub struct UTXOVarCRH {}

impl<F: PrimeField + Absorb + Absorbable> CRHSchemeGadget<UTXOCRH<F>, F> for UTXOVarCRH {
    type InputVar = UTXOVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = GriffinParamsVar<F>;

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
        GriffinSpongeVar::evaluate(parameters, &input)
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

pub struct BlockTreeVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<BlockTreeCRH<F>, F> for BlockTreeVarCRH<F> {
    type InputVar = BlockMetadataVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        CRHGadget::evaluate(
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

pub struct BlockTreeVarCRHGriffin<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb + Absorbable> CRHSchemeGadget<BlockTreeCRHGriffin<F>, F>
    for BlockTreeVarCRHGriffin<F>
{
    type InputVar = BlockMetadataVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = GriffinParamsVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        GriffinSpongeVar::evaluate(
            parameters,
            &vec![
                input.tx_tree_root.clone(),
                input.signer_tree_root.clone(),
                input.nullifier_tree_root.clone(),
                input.height.to_fp()?,
            ],
        )
    }
}

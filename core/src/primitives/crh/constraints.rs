use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    merkle_tree::{Config, constraints::ConfigGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

use super::{BlockCRH, BlockTreeCRH, NonceCRH, PublicKeyCRH, UTXOCRH};
use crate::{
    datastructures::{
        block::constraints::{BlockHashVar, BlockVar},
        keypair::constraints::PublicKeyVar,
        noncemap::constraints::NonceVar,
        nullifier::constraints::NullifierVar,
        shieldedtx::constraints::ShieldedTransactionVar,
        utxo::constraints::UTXOVar,
    },
    primitives::crh::{IdentityCRH, NullifierCRH},
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
pub struct UTXOVarCRH<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    _c: PhantomData<C>,
    _cv: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    CRHSchemeGadget<UTXOCRH<C>, C::BaseField> for UTXOVarCRH<C, CVar>
{
    type InputVar = UTXOVar<C, CVar>;
    type OutputVar = FpVar<C::BaseField>;
    type ParametersVar = CRHParametersVar<C::BaseField>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        let bool_as_fp: FpVar<C::BaseField> = input.is_dummy.clone().into();
        let pk_point = input.pk.key.to_constraint_field()?;
        let mut input = Vec::from([
            input.amount.clone(),
            bool_as_fp,
            input.salt.clone(),
        ]);
        for p in pk_point {
            input.push(p);
        }
        CRHGadget::evaluate(parameters, &input)
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

pub struct BlockVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<BlockCRH<F>, F> for BlockVarCRH<F> {
    type InputVar = BlockVar<F>;
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
                input.height.clone(),
            ],
        )
    }
}

pub struct BlockTreeVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<BlockTreeCRH<F>, F> for BlockTreeVarCRH<F> {
    type InputVar = BlockHashVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = ();

    fn evaluate(
        _parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        Ok(input.clone())
    }
}

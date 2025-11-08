use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, uint64::UInt64};

use crate::{datastructures::{
    block::constraints::BlockVar, keypair::constraints::PublicKeyVar,
    noncemap::constraints::NonceVar, transaction::constraints::TransactionVar,
    utxo::constraints::UTXOVar,
}, primitives::crh::CommittedUTXOCRH};

use super::{BlockCRH, NonceCRH, PublicKeyCRH, TransactionCRH, UTXOCRH};

pub struct TransactionVarCRH<C, CVar> {
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

pub struct NonceVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<C, CVar> Default for TransactionVarCRH<C, CVar> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, CVar> TransactionVarCRH<C, CVar> {
    pub fn new() -> Self {
        Self {
            _c: PhantomData,
            _cvar: PhantomData,
        }
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    CRHSchemeGadget<TransactionCRH<C>, C::BaseField> for TransactionVarCRH<C, CVar>
{
    type InputVar = TransactionVar<C, CVar>;
    type OutputVar = FpVar<C::BaseField>;
    type ParametersVar = CRHParametersVar<C::BaseField>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        let elements: Vec<FpVar<_>> = input.try_into()?;
        CRHGadget::evaluate(parameters, &elements)
    }
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

pub struct UTXOVarCRH<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>> {
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
        let mut input = Vec::from([input.amount.clone(), bool_as_fp]);
        for p in pk_point {
            input.push(p);
        }
        CRHGadget::evaluate(parameters, &input)
    }
}

pub struct CommittedUTXOVarCRH<F> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<CommittedUTXOCRH<F>, F> for CommittedUTXOVarCRH<F> {
    type InputVar = (FpVar<F>, UInt64<F>);
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        (cm, idx): &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::gr1cs::SynthesisError> {
        CRHGadget::evaluate(parameters, &[cm.clone(), idx.to_fp()?])
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
                input.utxo_tree_root.clone(),
                input.tx_tree_root.clone(),
                input.signer_tree_root.clone(),
                input.height.clone(),
            ],
        )
    }
}

use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError, SynthesisMode,
};
use ark_std::{borrow::Borrow, fmt::Debug, marker::PhantomData, rand::RngCore};
use sonobe_fs::{
    DeciderKey, FoldingInstanceVar, FoldingSchemeDef, FoldingSchemeGadgetDef,
    FoldingSchemeGadgetOpsFull, FoldingSchemeGadgetOpsPartial, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondary, GroupBasedFoldingSchemeSecondaryDef,
};
use sonobe_ivc::compilers::cyclefold::{FoldingSchemeCycleFoldExt, circuits::CycleFoldConfig};
use sonobe_primitives::{
    circuits::{ConstraintSystemExt, FCircuit},
    commitments::VectorCommitmentDef,
    relations::WitnessInstanceSampler,
    traits::{Dummy, SonobeCurve},
    transcripts::{Absorbable, AbsorbableGadget, Transcript, TranscriptVar},
};

pub struct AggregatorCircuitState<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> {
    V: FS1::RU,
    cf_U: FS2::RU,
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Clone for AggregatorCircuitState<FS1, FS2> {
    fn clone(&self) -> Self {
        Self {
            V: self.V.clone(),
            cf_U: self.cf_U.clone(),
        }
    }
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Debug for AggregatorCircuitState<FS1, FS2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregatorCircuitState")
            .field("V", &self.V)
            .field("cf_U", &self.cf_U)
            .finish()
    }
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> PartialEq for AggregatorCircuitState<FS1, FS2> {
    fn eq(&self, other: &Self) -> bool {
        self.V == other.V && self.cf_U == other.cf_U
    }
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Eq for AggregatorCircuitState<FS1, FS2> {}

pub struct AggregatorCircuitStateVar<
    FS1: GroupBasedFoldingSchemePrimaryDef,
    FS2: GroupBasedFoldingSchemeSecondaryDef,
> {
    V: <FS1::Gadget as FoldingSchemeGadgetDef>::RU,
    cf_U: <FS2::Gadget as FoldingSchemeGadgetDef>::RU,
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Absorbable for AggregatorCircuitState<FS1, FS2> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.V.absorb_into(dest);
    }
}

impl<FS1: GroupBasedFoldingSchemePrimaryDef, FS2: GroupBasedFoldingSchemeSecondaryDef>
    AbsorbableGadget<FS1::TranscriptField> for AggregatorCircuitStateVar<FS1, FS2>
{
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<FS1::TranscriptField>>,
    ) -> Result<(), SynthesisError> {
        self.V.absorb_into(dest)
    }
}

impl<
    FS1: GroupBasedFoldingSchemePrimaryDef,
    FS2: GroupBasedFoldingSchemeSecondaryDef<
        VC: VectorCommitmentDef<Commitment: SonobeCurve<BaseField = FS1::TranscriptField>>,
    >,
> AllocVar<AggregatorCircuitState<FS1, FS2>, FS1::TranscriptField>
    for AggregatorCircuitStateVar<FS1, FS2>
{
    fn new_variable<T: Borrow<AggregatorCircuitState<FS1, FS2>>>(
        cs: impl Into<Namespace<FS1::TranscriptField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let AggregatorCircuitState { V, cf_U } = v.borrow();
        Ok(Self {
            V: AllocVar::new_variable(cs.clone(), || Ok(V), mode)?,
            cf_U: AllocVar::new_variable(cs, || Ok(cf_U), mode)?,
        })
    }
}

impl<
    FS1: GroupBasedFoldingSchemePrimaryDef,
    FS2: GroupBasedFoldingSchemeSecondaryDef<
        VC: VectorCommitmentDef<Commitment: SonobeCurve<BaseField = FS1::TranscriptField>>,
    >,
> GR1CSVar<FS1::TranscriptField> for AggregatorCircuitStateVar<FS1, FS2>
{
    type Value = AggregatorCircuitState<FS1, FS2>;

    fn cs(&self) -> ConstraintSystemRef<FS1::TranscriptField> {
        self.V.cs().or(self.cf_U.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(AggregatorCircuitState {
            V: self.V.value()?,
            cf_U: self.cf_U.value()?,
        })
    }
}

pub struct AggregatorCircuitExternalInputs<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef, R: RngCore>
{
    Y: FS1::RW,
    WW: FS1::RW,
    U: FS1::RU,
    u: FS1::IU,
    proof: FS1::Proof<1, 1>,
    cf_W: FS2::RW,

    rng: R,
}

pub struct AggregatorCircuitExternalOutputs<
    FS1: FoldingSchemeDef,
    FS2: FoldingSchemeDef,
    R: RngCore,
> {
    YY: FS1::RW,
    cf_WW: FS2::RW,
    rng: R,
}

pub struct AggregatorCircuit<
    T: Transcript<FS1::TranscriptField>,
    FS1: FoldingSchemeDef,
    FS2: FoldingSchemeDef,
    R,
> {
    hash_config: T::Config,
    pp_hash: <FS1::VC as VectorCommitmentDef>::Scalar,
    dk1: FS1::DeciderKey,
    dk2: FS2::DeciderKey,
    _r: PhantomData<R>,
}

impl<
    T: Transcript<FS1::TranscriptField>,
    FS1: FoldingSchemeCycleFoldExt<
            2,
            0,
            Gadget: FoldingSchemeGadgetOpsPartial<2, 0, VerifierKey = ()>,
            VC: VectorCommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::VC as VectorCommitmentDef>::Scalar>,
            >,
        > + FoldingSchemeCycleFoldExt<
            1,
            1,
            Gadget: FoldingSchemeGadgetOpsPartial<1, 1, VerifierKey = ()>,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Gadget: FoldingSchemeGadgetOpsFull<1, 1, VerifierKey = ()>,
            VC: VectorCommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::VC as VectorCommitmentDef>::Scalar>,
            >,
        >,
    R: RngCore + Default,
> FCircuit for AggregatorCircuit<T, FS1, FS2, R>
{
    type Field = <FS1::VC as VectorCommitmentDef>::Scalar;

    type State = AggregatorCircuitState<FS1, FS2>;

    type StateVar = AggregatorCircuitStateVar<FS1, FS2>;

    type ExternalInputs = AggregatorCircuitExternalInputs<FS1, FS2, R>;
    type ExternalOutputs = AggregatorCircuitExternalOutputs<FS1, FS2, R>;

    fn dummy_state(&self) -> Self::State {
        AggregatorCircuitState {
            V: FS1::RU::dummy(self.dk1.to_arith_config()),
            cf_U: FS2::RU::dummy(self.dk2.to_arith_config()),
        }
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {
        AggregatorCircuitExternalInputs {
            Y: FS1::RW::dummy(self.dk1.to_arith_config()),
            WW: FS1::RW::dummy(self.dk1.to_arith_config()),
            U: FS1::RU::dummy(self.dk1.to_arith_config()),
            u: FS1::IU::dummy(self.dk1.to_arith_config()),
            proof: FS1::Proof::dummy(self.dk1.to_arith_config()),
            cf_W: FS2::RW::dummy(self.dk2.to_arith_config()),
            rng: R::default(),
        }
    }

    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ConstraintSystemRef<Self::Field>,
        _i: FpVar<Self::Field>,
        z_i: Self::StateVar,
        external_inputs: Self::ExternalInputs, // inputs that are not part of the state
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let hash = T::new_with_pp_hash(&self.hash_config, self.pp_hash);
        let mut transcript2_native = hash.separate_domain("transcript2".as_ref());
        let hash = T::Var::new_with_pp_hash(
            &self.hash_config,
            &FpVar::new_witness(cs.clone(), || Ok(self.pp_hash))?,
        )?;
        let mut transcript1 = hash.separate_domain("transcript1".as_ref())?;
        let mut transcript2 = hash.separate_domain("transcript2".as_ref())?;

        let AggregatorCircuitStateVar { V, cf_U } = z_i;

        let AggregatorCircuitExternalInputs {
            WW,
            Y,
            U,
            u,
            proof,
            mut cf_W,
            mut rng,
        } = external_inputs;
        let U = <FS1::Gadget as FoldingSchemeGadgetDef>::RU::new_witness(cs.clone(), || Ok(U))?;
        let u = <FS1::Gadget as FoldingSchemeGadgetDef>::IU::new_witness(cs.clone(), || Ok(u))?;
        let proof =
            <FS1::Gadget as FoldingSchemeGadgetDef>::Proof::new_witness(cs.clone(), || Ok(proof))?;

        let (UU, rho) = FS1::Gadget::verify_hinted(&(), &mut transcript1, [&U], [&u], &proof)?;

        let (YY, proof2, cf_us, cf_proofs) = if cs.is_in_setup_mode() {
            (
                Dummy::dummy(self.dk1.to_arith_config()),
                Dummy::dummy(self.dk1.to_arith_config()),
                vec![
                    Dummy::dummy(self.dk2.to_arith_config());
                    <FS1 as FoldingSchemeCycleFoldExt<1, 1>>::N_CYCLEFOLDS
                        + <FS1 as FoldingSchemeCycleFoldExt<2, 0>>::N_CYCLEFOLDS
                ],
                vec![
                    Dummy::dummy(self.dk2.to_arith_config());
                    <FS1 as FoldingSchemeCycleFoldExt<1, 1>>::N_CYCLEFOLDS
                        + <FS1 as FoldingSchemeCycleFoldExt<2, 0>>::N_CYCLEFOLDS
                ],
            )
        } else {
            let V = V.value()?;
            let UU = UU.value()?;
            let (YY, _, proof2, challenge2) = FS1::prove(
                self.dk1.to_pk(),
                &mut transcript2_native,
                &[WW, Y],
                &[&UU, &V],
                &[] as &[&FS1::IW; 0],
                &[] as &[&FS1::IU; 0],
                &mut rng,
            )
            .map_err(|_| SynthesisError::Unsatisfiable)?;

            let U = U.value()?;
            let u = u.value()?;
            let proof = proof.value()?;
            let challenge = rho.value()?;

            let mut cf_U = cf_U.value()?;

            let mut cf_us = vec![];
            let mut cf_proofs = vec![];

            let cf_configs1 = FS1::to_cyclefold_configs(&[U], &[u], &proof, challenge);
            let cf_configs2 =
                FS1::to_cyclefold_configs(&[UU, V], &[] as &[&FS1::IU; 0], &proof2, challenge2);
            for cfg in cf_configs1 {
                let cs = ConstraintSystem::new_ref();
                cs.set_mode(SynthesisMode::Prove {
                    construct_matrices: false,
                    generate_lc_assignments: false,
                });
                cfg.verify_point_rlc(cs.clone())?;

                let (cf_w, cf_u) = self
                    .dk2
                    .sample(cs.assignments()?, &mut rng)
                    .map_err(|_| SynthesisError::AssignmentMissing)?;

                let cf_proof;
                (cf_W, cf_U, cf_proof, _) = FS2::prove(
                    self.dk2.to_pk(),
                    &mut transcript2_native,
                    &[&cf_W],
                    &[&cf_U],
                    &[&cf_w],
                    &[&cf_u],
                    &mut rng,
                )
                .map_err(|_| SynthesisError::Unsatisfiable)?;
                cf_us.push(cf_u);
                cf_proofs.push(cf_proof);
            }
            for cfg in cf_configs2 {
                let cs = ConstraintSystem::new_ref();
                cs.set_mode(SynthesisMode::Prove {
                    construct_matrices: false,
                    generate_lc_assignments: false,
                });
                cfg.verify_point_rlc(cs.clone())?;

                let (cf_w, cf_u) = self
                    .dk2
                    .sample(cs.assignments()?, &mut rng)
                    .map_err(|_| SynthesisError::AssignmentMissing)?;

                let cf_proof;
                (cf_W, cf_U, cf_proof, _) = FS2::prove(
                    self.dk2.to_pk(),
                    &mut transcript2_native,
                    &[&cf_W],
                    &[&cf_U],
                    &[&cf_w],
                    &[&cf_u],
                    &mut rng,
                )
                .map_err(|_| SynthesisError::Unsatisfiable)?;
                cf_us.push(cf_u);
                cf_proofs.push(cf_proof);
            }

            (YY, proof2, cf_us, cf_proofs)
        };
        let proof2 =
            <FS1::Gadget as FoldingSchemeGadgetDef>::Proof::new_witness(cs.clone(), || Ok(proof2))?;

        let (VV, rho2) = FS1::Gadget::verify_hinted(&(), &mut transcript2, [&UU, &V], [], &proof2)?;

        let cf_proofs = Vec::new_witness(cs.clone(), || Ok(cf_proofs))?;

        let mut cf_UU = cf_U;
        for ((cf_u, cf_u_x), cf_proof) in cf_us
            .iter()
            .zip(
                FS1::to_cyclefold_inputs([U], [u], UU.clone(), proof, rho)?
                    .into_iter()
                    .chain(FS1::to_cyclefold_inputs(
                        [UU, V],
                        [],
                        VV.clone(),
                        proof2,
                        rho2,
                    )?),
            )
            .zip(&cf_proofs)
        {
            let cf_u =
                FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), cf_u, cf_u_x)?;
            cf_UU = FS2::Gadget::verify(&(), &mut transcript2, [&cf_UU], [&cf_u], cf_proof)?;
        }

        Ok((
            AggregatorCircuitStateVar { V: VV, cf_U: cf_UU },
            AggregatorCircuitExternalOutputs {
                YY,
                cf_WW: cf_W,
                rng,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as C1};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_relations::gr1cs::ConstraintSynthesizer;
    use ark_std::{
        error::Error,
        rand::{rngs::ThreadRng, thread_rng},
        sync::Arc,
        test_rng,
    };
    use sonobe_fs::{FoldingSchemeOps, nova::Nova, ova::CycleFoldOva};
    use sonobe_ivc::{
        IVC, IVCStatefulProver,
        compilers::cyclefold::{CycleFoldBasedIVC, circuits::CycleFoldCircuit},
    };
    use sonobe_primitives::{
        circuits::{
            AssignmentsOwned, ConstraintSystemBuilder,
            utils::{CircuitForTest, satisfying_assignments_for_test},
        },
        commitments::pedersen::Pedersen,
        traits::CF1,
        transcripts::griffin::{GriffinParams, sponge::GriffinSponge},
    };

    use super::*;

    pub fn test_ivc<FS1, FS2, T>(
        config: (FS1::Config, FS2::Config, T::Config),
        config_f: FS1::Config,
        user_circuit: impl ConstraintSynthesizer<<FS1::VC as VectorCommitmentDef>::Scalar>,
        assignments_vec: Vec<AssignmentsOwned<<FS1::VC as VectorCommitmentDef>::Scalar>>,
    ) -> Result<(), Box<dyn Error>>
    where
        FS1: FoldingSchemeCycleFoldExt<
                1,
                1,
                Arith: From<ConstraintSystem<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>>,
                Gadget: FoldingSchemeGadgetOpsPartial<1, 1, VerifierKey = ()>,
                VC: VectorCommitmentDef<
                    Commitment: SonobeCurve<BaseField = <FS2::VC as VectorCommitmentDef>::Scalar>,
                >,
            > + FoldingSchemeCycleFoldExt<
                2,
                0,
                Gadget: FoldingSchemeGadgetOpsPartial<2, 0, VerifierKey = ()>,
            >,
        FS2: GroupBasedFoldingSchemeSecondary<
                1,
                1,
                Arith: From<ConstraintSystem<CF1<<FS2::VC as VectorCommitmentDef>::Commitment>>>,
                PublicParam: Clone,
                Gadget: FoldingSchemeGadgetOpsFull<1, 1, VerifierKey = ()>,
                VC: VectorCommitmentDef<
                    Commitment: SonobeCurve<BaseField = <FS1::VC as VectorCommitmentDef>::Scalar>,
                >,
            >,
        T: Transcript<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>,
    {
        let mut rng1 = test_rng();

        let hash_config = config.2.clone();

        let pp = CycleFoldBasedIVC::<FS1, FS2, T>::preprocess(config, &mut rng1)?;

        let pp_f = <FS1 as FoldingSchemeOps<1, 1>>::preprocess(config_f, &mut rng1)?;

        let cyclefold_circuit =
            CycleFoldCircuit::<<FS1 as FoldingSchemeCycleFoldExt<1, 1>>::CFConfig>::default();

        let cs = ConstraintSystemBuilder::new()
            .with_setup_mode()
            .with_circuit(cyclefold_circuit)
            .synthesize()?;
        let arith2 = FS2::Arith::from(cs);
        let dk2 = FS2::generate_keys(pp.1.clone(), arith2)?;

        let cs = ConstraintSystemBuilder::new()
            .with_setup_mode()
            .with_circuit(user_circuit)
            .synthesize()?;
        let arith1 = FS1::Arith::from(cs);

        let dk1 = <FS1 as FoldingSchemeOps<1, 1>>::generate_keys(pp_f, arith1)?;

        let mut WWs = vec![];
        let mut Us = vec![];
        let mut us = vec![];
        let mut proofs = vec![];

        for assignments in assignments_vec {
            let hash = T::new_with_pp_hash(&hash_config, Default::default());
            let mut transcript1 = hash.separate_domain("transcript1".as_ref());

            let (W, U) = dk1.sample((), &mut rng1)?;
            let (w, u) = dk1.sample(assignments, &mut rng1)?;
            let (WW, _, proof, _) = FS1::prove(
                dk1.to_pk(),
                &mut transcript1,
                &[&W],
                &[&U],
                &[&w],
                &[&u],
                &mut rng1,
            )?;
            WWs.push(WW);
            Us.push(U);
            us.push(u);
            proofs.push(proof);
        }

        let step_circuit = AggregatorCircuit::<T, FS1, FS2, _> {
            hash_config,
            pp_hash: Default::default(),
            dk1: dk1.clone(),
            dk2: dk2.clone(),
            _r: PhantomData,
        };

        let (pk, vk) = CycleFoldBasedIVC::<FS1, FS2, T>::generate_keys(pp, &step_circuit)?;

        let initial_state = step_circuit.dummy_state();

        let mut prover = IVCStatefulProver::<_, CycleFoldBasedIVC<FS1, FS2, T>>::new(
            pk,
            step_circuit,
            initial_state,
        )?;

        let mut Y = FS1::RW::dummy(dk1.to_arith_config());
        let mut cf_W = FS2::RW::dummy(dk2.to_arith_config());
        let mut rng = thread_rng();

        for ((WW, U), (u, proof)) in WWs
            .into_iter()
            .zip(Us.into_iter())
            .zip(us.into_iter().zip(proofs.into_iter()))
        {
            let external_outputs = prover.prove_step(
                AggregatorCircuitExternalInputs {
                    Y,
                    WW,
                    U,
                    u,
                    proof,
                    cf_W,
                    rng,
                },
                &mut rng1,
            )?;
            rng = external_outputs.rng;
            Y = external_outputs.YY;
            cf_W = external_outputs.cf_WW;

            CycleFoldBasedIVC::<FS1, FS2, T>::verify::<AggregatorCircuit<T, FS1, FS2, ThreadRng>>(
                &vk,
                prover.i,
                &prover.initial_state,
                &prover.current_state,
                &prover.current_proof,
            )?;

            <FS1 as FoldingSchemeOps<1, 1>>::decide_running(&dk1, &Y, &prover.current_state.V)?;
            FS2::decide_running(&dk2, &cf_W, &prover.current_state.cf_U)?;
        }

        Ok(())
    }

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let rounds = 20;

        test_ivc::<Nova<Pedersen<C1, true>>, CycleFoldOva<Pedersen<C2, true>>, GriffinSponge<_>>(
            (
                1 << 18,
                (2048, 2048),
                Arc::new(GriffinParams::new(16, 5, 9)),
            ),
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
        )
    }
}

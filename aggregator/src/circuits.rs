use ark_crypto_primitives::{crh::poseidon::constraints::CRHParametersVar, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError, SynthesisMode,
};
use ark_std::{borrow::Borrow, fmt::Debug, marker::PhantomData, rand::RngCore};
use nmerkle_trees::sparse::{NArySparsePath, constraints::NArySparsePathVar};
use num_bigint::BigUint;
use plasmablind_core::datastructures::{
    shieldedtx::constraints::UTXOTreeGadget,
    signerlist::constraints::{SignerTreeConfigGadget, SparseNArySignerTreeConfigGadget},
    txtree::{TRANSACTION_TREE_ARITY, TransactionTreeConfig},
};
use plasmablind_core::datastructures::{
    signerlist::NARY_SIGNER_TREE_HEIGHT,
    txtree::{NARY_TRANSACTION_TREE_HEIGHT, constraints::TransactionTreeGadget},
};
use plasmablind_core::{
    NULLIFIER_TREE_HEIGHT, datastructures::signerlist::constraints::SignerTreeGadget,
};
use plasmablind_core::{
    config::PlasmaBlindConfig, datastructures::nullifier::constraints::NullifierTreeGadgeet,
};
use plasmablind_core::{
    config::PlasmaBlindConfigVar,
    datastructures::{
        TX_IO_SIZE,
        shieldedtx::{ShieldedTransaction, constraints::ShieldedTransactionVar},
        signerlist::{SIGNER_TREE_ARITY, SignerTreeConfig, SparseNArySignerTreeConfig},
        txtree::{
            SparseNAryTransactionTreeConfig,
            constraints::{SparseNAryTransactionTreeConfigGadget, TransactionTreeConfigGadget},
        },
    },
};
use sonobe_fs::{
    DeciderKey, FoldingInstance, FoldingInstanceVar, FoldingSchemeDef, FoldingSchemeGadgetDef,
    FoldingSchemeGadgetOpsFull, FoldingSchemeGadgetOpsPartial, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondary, GroupBasedFoldingSchemeSecondaryDef,
};
use sonobe_ivc::compilers::cyclefold::{FoldingSchemeCycleFoldExt, circuits::CycleFoldConfig};
use sonobe_primitives::{
    algebra::ops::bits::ToBitsGadgetExt,
    circuits::{ConstraintSystemExt, FCircuit},
    commitments::{VectorCommitmentDef, VectorCommitmentGadgetDef},
    relations::WitnessInstanceSampler,
    traits::{Dummy, SonobeCurve},
    transcripts::{Absorbable, AbsorbableGadget, Transcript, TranscriptVar},
};

pub struct AggregatorCircuitState<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> {
    pub V: FS1::RU,
    pub cf_U: FS2::RU,

    pub tx_index: usize,
    pub tx_root: <FS1::VC as VectorCommitmentDef>::Scalar,
    pub nullifier_root: <FS1::VC as VectorCommitmentDef>::Scalar,
    pub signer_root: <FS1::VC as VectorCommitmentDef>::Scalar,
    pub block_root: <FS1::VC as VectorCommitmentDef>::Scalar,
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Clone for AggregatorCircuitState<FS1, FS2> {
    fn clone(&self) -> Self {
        Self {
            V: self.V.clone(),
            cf_U: self.cf_U.clone(),

            tx_index: self.tx_index.clone(),
            tx_root: self.tx_root,
            nullifier_root: self.nullifier_root,
            signer_root: self.signer_root,
            block_root: self.block_root,
        }
    }
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Debug for AggregatorCircuitState<FS1, FS2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregatorCircuitState")
            .field("V", &self.V)
            .field("cf_U", &self.cf_U)
            .field("tx_index", &self.tx_index)
            .field("tx_root", &self.tx_root)
            .field("nullifier_root", &self.nullifier_root)
            .field("signer_root", &self.signer_root)
            .field("block_root", &self.block_root)
            .finish()
    }
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> PartialEq for AggregatorCircuitState<FS1, FS2> {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            V,
            cf_U,
            tx_index,
            tx_root,
            nullifier_root,
            signer_root,
            block_root,
        } = self;

        V == &other.V
            && cf_U == &other.cf_U
            && tx_index == &other.tx_index
            && tx_root == &other.tx_root
            && nullifier_root == &other.nullifier_root
            && signer_root == &other.signer_root
            && block_root == &other.block_root
    }
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Eq for AggregatorCircuitState<FS1, FS2> {}

pub struct AggregatorCircuitStateVar<FS1: FoldingSchemeGadgetDef, FS2: FoldingSchemeGadgetDef> {
    V: FS1::RU,
    cf_U: FS2::RU,

    tx_index: <FS1::VC as VectorCommitmentGadgetDef>::ScalarVar,
    tx_root: <FS1::VC as VectorCommitmentGadgetDef>::ScalarVar,
    nullifier_root: <FS1::VC as VectorCommitmentGadgetDef>::ScalarVar,
    signer_root: <FS1::VC as VectorCommitmentGadgetDef>::ScalarVar,
    block_root: <FS1::VC as VectorCommitmentGadgetDef>::ScalarVar,
}

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> Absorbable for AggregatorCircuitState<FS1, FS2> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let Self {
            V,
            cf_U,
            tx_index,
            tx_root,
            nullifier_root,
            signer_root,
            block_root,
        } = self;

        V.absorb_into(dest);
        cf_U.absorb_into(dest);
        tx_index.absorb_into(dest);
        tx_root.absorb_into(dest);
        nullifier_root.absorb_into(dest);
        signer_root.absorb_into(dest);
        block_root.absorb_into(dest);
    }
}

impl<
    FS1: FoldingSchemeGadgetDef,
    FS2: FoldingSchemeGadgetDef<
        VC: VectorCommitmentGadgetDef<
            ConstraintField = <FS1::VC as VectorCommitmentGadgetDef>::ConstraintField,
        >,
    >,
> AbsorbableGadget<<FS1::VC as VectorCommitmentGadgetDef>::ConstraintField>
    for AggregatorCircuitStateVar<FS1, FS2>
{
    fn absorb_into(
        &self,
        dest: &mut Vec<FpVar<<FS1::VC as VectorCommitmentGadgetDef>::ConstraintField>>,
    ) -> Result<(), SynthesisError> {
        let Self {
            V,
            cf_U,
            tx_index,
            tx_root,
            nullifier_root,
            signer_root,
            block_root,
        } = self;

        V.absorb_into(dest)?;
        cf_U.absorb_into(dest)?;
        tx_index.absorb_into(dest)?;
        tx_root.absorb_into(dest)?;
        nullifier_root.absorb_into(dest)?;
        signer_root.absorb_into(dest)?;
        block_root.absorb_into(dest)?;
        Ok(())
    }
}

impl<
    FS1: GroupBasedFoldingSchemePrimaryDef,
    FS2: GroupBasedFoldingSchemeSecondaryDef<
        VC: VectorCommitmentDef<Commitment: SonobeCurve<BaseField = FS1::TranscriptField>>,
    >,
> AllocVar<AggregatorCircuitState<FS1, FS2>, FS1::TranscriptField>
    for AggregatorCircuitStateVar<FS1::Gadget, FS2::Gadget>
{
    fn new_variable<T: Borrow<AggregatorCircuitState<FS1, FS2>>>(
        cs: impl Into<Namespace<FS1::TranscriptField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let AggregatorCircuitState {
            V,
            cf_U,
            tx_index,
            tx_root,
            nullifier_root,
            signer_root,
            block_root,
        } = v.borrow();
        Ok(Self {
            V: AllocVar::new_variable(cs.clone(), || Ok(V), mode)?,
            cf_U: AllocVar::new_variable(cs.clone(), || Ok(cf_U), mode)?,
            tx_index: AllocVar::new_variable(
                cs.clone(),
                || Ok(FS1::TranscriptField::from(*tx_index as u64)),
                mode,
            )?,
            tx_root: AllocVar::new_variable(cs.clone(), || Ok(tx_root), mode)?,
            nullifier_root: AllocVar::new_variable(cs.clone(), || Ok(nullifier_root), mode)?,
            signer_root: AllocVar::new_variable(cs.clone(), || Ok(signer_root), mode)?,
            block_root: AllocVar::new_variable(cs, || Ok(block_root), mode)?,
        })
    }
}

impl<
    FS1: FoldingSchemeGadgetDef,
    FS2: FoldingSchemeGadgetDef<
        VC: VectorCommitmentGadgetDef<
            ConstraintField = <FS1::VC as VectorCommitmentGadgetDef>::ConstraintField,
        >,
    >,
> GR1CSVar<<FS1::VC as VectorCommitmentGadgetDef>::ConstraintField>
    for AggregatorCircuitStateVar<FS1, FS2>
{
    type Value = AggregatorCircuitState<FS1::Native, FS2::Native>;

    fn cs(&self) -> ConstraintSystemRef<<FS1::VC as VectorCommitmentGadgetDef>::ConstraintField> {
        self.V
            .cs()
            .or(self.cf_U.cs())
            .or(self.tx_index.cs())
            .or(self.tx_root.cs())
            .or(self.nullifier_root.cs())
            .or(self.signer_root.cs())
            .or(self.block_root.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let tx_index = self.tx_index.value()?.into_bigint();
        let tx_index: BigUint = tx_index.into();

        Ok(AggregatorCircuitState {
            V: self.V.value()?,
            cf_U: self.cf_U.value()?,
            tx_index: tx_index
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
            tx_root: self.tx_root.value()?,
            nullifier_root: self.nullifier_root.value()?,
            signer_root: self.signer_root.value()?,
            block_root: self.block_root.value()?,
        })
    }
}

pub struct AggregatorCircuitExternalInputs<
    FS1: FoldingSchemeDef<TranscriptField: Absorb>,
    FS2: FoldingSchemeDef,
    R: RngCore,
> {
    pub Y: FS1::RW,
    pub cf_W: FS2::RW,

    pub WW: FS1::RW,
    pub U: FS1::RU,
    pub u: FS1::IU,
    pub proof: FS1::Proof<1, 1>,

    pub pk: FS1::TranscriptField,
    pub tx: ShieldedTransaction<FS1::TranscriptField>,

    pub nullifier_intervals: [(FS1::TranscriptField, FS1::TranscriptField); TX_IO_SIZE],

    pub tx_tree_inclusion_proof: NArySparsePath<
        TRANSACTION_TREE_ARITY,
        TransactionTreeConfig<FS1::TranscriptField>,
        SparseNAryTransactionTreeConfig<FS1::TranscriptField>,
    >,
    pub next_tx_index: usize,

    pub nullifier_tree_replacement_proofs: [Vec<FS1::TranscriptField>; TX_IO_SIZE],
    pub nullifier_tree_insertion_proofs: [Vec<FS1::TranscriptField>; TX_IO_SIZE],
    pub nullifier_tree_replacement_positions: [usize; TX_IO_SIZE],
    pub nullifier_tree_insertion_positions: [usize; TX_IO_SIZE],
    pub signer_tree_inclusion_proof: NArySparsePath<
        SIGNER_TREE_ARITY,
        SignerTreeConfig<FS1::TranscriptField>,
        SparseNArySignerTreeConfig<FS1::TranscriptField>,
    >,

    pub rng: R,
}

pub struct AggregatorCircuitExternalOutputs<
    FS1: FoldingSchemeDef,
    FS2: FoldingSchemeDef,
    R: RngCore,
> {
    pub YY: FS1::RW,
    pub cf_WW: FS2::RW,
    pub rng: R,
}

pub struct AggregatorCircuit<
    T: Transcript<FS1::TranscriptField>,
    FS1: FoldingSchemeDef,
    FS2: FoldingSchemeDef,
    R,
> {
    pub hash_config: T::Config,
    pub config: PlasmaBlindConfig<FS1::TranscriptField>,
    pub pp_hash: <FS1::VC as VectorCommitmentDef>::Scalar,
    pub dk1: FS1::DeciderKey,
    pub dk2: FS2::DeciderKey,
    pub _r: PhantomData<(R)>,
}

impl<
    T: Transcript<FS1::TranscriptField>,
    FS1: FoldingSchemeCycleFoldExt<
            2,
            0,
            Gadget: FoldingSchemeGadgetOpsPartial<2, 0, VerifierKey = ()>,
            VC: VectorCommitmentDef<
                Commitment: SonobeCurve<
                    BaseField = <FS2::VC as VectorCommitmentDef>::Scalar,
                    ScalarField: Absorb,
                >,
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
                Commitment: SonobeCurve<
                    BaseField = <FS1::VC as VectorCommitmentDef>::Scalar,
                    ScalarField: Absorb,
                >,
            >,
        >,
    R: RngCore + Default,
> FCircuit for AggregatorCircuit<T, FS1, FS2, R>
{
    type Field = <FS1::VC as VectorCommitmentDef>::Scalar;

    type State = AggregatorCircuitState<FS1, FS2>;

    type StateVar = AggregatorCircuitStateVar<FS1::Gadget, FS2::Gadget>;

    type ExternalInputs = AggregatorCircuitExternalInputs<FS1, FS2, R>;
    type ExternalOutputs = AggregatorCircuitExternalOutputs<FS1, FS2, R>;

    fn dummy_state(&self) -> Self::State {
        AggregatorCircuitState {
            V: FS1::RU::dummy(self.dk1.to_arith_config()),
            cf_U: FS2::RU::dummy(self.dk2.to_arith_config()),
            tx_index: Default::default(),
            tx_root: Default::default(),
            nullifier_root: Default::default(),
            signer_root: Default::default(),
            block_root: Default::default(),
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

            pk: Default::default(),
            tx: Default::default(),

            nullifier_intervals: Default::default(),

            next_tx_index: Default::default(),
            tx_tree_inclusion_proof: Default::default(),
            nullifier_tree_replacement_proofs: [
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
            ],
            nullifier_tree_insertion_proofs: [
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
                vec![Default::default(); NULLIFIER_TREE_HEIGHT - 1],
            ],
            nullifier_tree_replacement_positions: Default::default(),
            nullifier_tree_insertion_positions: Default::default(),
            rng: R::default(),
            signer_tree_inclusion_proof: Default::default(),
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

        let AggregatorCircuitStateVar {
            V,
            cf_U,
            tx_index,
            tx_root,
            mut nullifier_root,
            signer_root,
            block_root,
        } = z_i;

        let AggregatorCircuitExternalInputs {
            WW,
            Y,
            U,
            u,
            proof,
            mut cf_W,

            pk,
            tx,

            nullifier_intervals,

            next_tx_index,
            tx_tree_inclusion_proof,
            nullifier_tree_replacement_proofs,
            nullifier_tree_insertion_proofs,
            nullifier_tree_replacement_positions,
            nullifier_tree_insertion_positions,

            mut rng,
            signer_tree_inclusion_proof,
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
                FS1::to_cyclefold_inputs([U], [u.clone()], UU.clone(), proof, rho)?
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

        let utxo_tree = UTXOTreeGadget::new(
            self.config.shielded_tx_leaf_config,
            CRHParametersVar::new_constant(cs.clone(), &self.config.shielded_tx_two_to_one_config)?,
        );

        let nullifier_tree = NullifierTreeGadgeet::new(
            CRHParametersVar::new_constant(cs.clone(), &self.config.nullifier_tree_leaf_config)?,
            CRHParametersVar::new_constant(
                cs.clone(),
                &self.config.nullifier_tree_two_to_one_config,
            )?,
        );

        let pk = FpVar::new_witness(cs.clone(), || Ok(pk))?;
        let tx = ShieldedTransactionVar::new_witness(cs.clone(), || Ok(tx))?;

        let nullifier_intervals = nullifier_intervals
            .iter()
            .map(|(l, u)| {
                Ok((
                    FpVar::new_witness(cs.clone(), || Ok(l))?,
                    FpVar::new_witness(cs.clone(), || Ok(u))?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let next_tx_index = FpVar::new_witness(cs.clone(), || {
            Ok(FS1::TranscriptField::from(next_tx_index as u64))
        })?;

        let tx_tree_inclusion_proof =
            NArySparsePathVar::<
                TRANSACTION_TREE_ARITY,
                TransactionTreeConfig<FS1::TranscriptField>,
                TransactionTreeConfigGadget<FS1::TranscriptField>,
                FS1::TranscriptField,
                SparseNAryTransactionTreeConfig<FS1::TranscriptField>,
                SparseNAryTransactionTreeConfigGadget<FS1::TranscriptField>,
            >::new_witness(cs.clone(), || Ok(tx_tree_inclusion_proof))?;

        let signer_tree_inclusion_proof =
            NArySparsePathVar::<
                SIGNER_TREE_ARITY,
                SignerTreeConfig<FS1::TranscriptField>,
                SignerTreeConfigGadget<FS1::TranscriptField>,
                FS1::TranscriptField,
                SparseNArySignerTreeConfig<FS1::TranscriptField>,
                SparseNArySignerTreeConfigGadget<FS1::TranscriptField>,
            >::new_witness(cs.clone(), || Ok(signer_tree_inclusion_proof))?;

        let nullifier_tree_replacement_proofs = nullifier_tree_replacement_proofs
            .iter()
            .map(|p| Vec::new_witness(cs.clone(), || Ok(&p[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let nullifier_tree_insertion_proofs = nullifier_tree_insertion_proofs
            .iter()
            .map(|p| Vec::new_witness(cs.clone(), || Ok(&p[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let nullifier_tree_replacement_positions = Vec::new_witness(cs.clone(), || {
            Ok(nullifier_tree_replacement_positions
                .into_iter()
                .map(|i| FS1::TranscriptField::from(i as u64))
                .collect::<Vec<_>>())
        })?;
        let nullifier_tree_insertion_positions = Vec::new_witness(cs.clone(), || {
            Ok(nullifier_tree_insertion_positions
                .into_iter()
                .map(|i| FS1::TranscriptField::from(i as u64))
                .collect::<Vec<_>>())
        })?;

        u.public_inputs().enforce_equal(
            &[
                &[pk.clone()][..],
                &tx.input_nullifiers
                    .iter()
                    .map(|i| i.value.clone())
                    .collect::<Vec<_>>(),
                &tx.output_utxo_commitments[..],
                &[block_root.clone()][..],
            ]
            .concat(),
        )?;

        let plasma_blind_config_var = PlasmaBlindConfigVar::new_variable(
            cs.clone(),
            || Ok(self.config.clone()),
            AllocationMode::Constant,
        )?;

        tx_tree_inclusion_proof
            .verify_membership(
                &(),
                &plasma_blind_config_var.tx_tree_n_to_one_config,
                &tx_root,
                &utxo_tree.build_root(&tx.output_utxo_commitments)?,
            )?
            .enforce_equal(&Boolean::constant(true))?;

        for j in 0..TX_IO_SIZE {
            let is_dummy = tx.input_nullifiers[j].value.is_zero()?;

            (&tx.input_nullifiers[j].value - &nullifier_intervals[j].0 - FpVar::one())
                .to_n_bits_le(FS1::TranscriptField::MODULUS_BIT_SIZE as usize - 1)?;
            (&nullifier_intervals[j].1 - &tx.input_nullifiers[j].value - FpVar::one())
                .to_n_bits_le(FS1::TranscriptField::MODULUS_BIT_SIZE as usize - 1)?;

            let (nullifier_root_old, nullifier_root_new) = nullifier_tree.update_root(
                &nullifier_intervals[j],
                &(
                    nullifier_intervals[j].0.clone(),
                    tx.input_nullifiers[j].value.clone(),
                ),
                &nullifier_tree_replacement_positions[j],
                &nullifier_tree_replacement_proofs[j],
            )?;
            nullifier_root_old.conditional_enforce_equal(&nullifier_root, &!&is_dummy)?;
            nullifier_root = is_dummy.select(&nullifier_root, &nullifier_root_new)?;

            let (nullifier_root_old, nullifier_root_new) = nullifier_tree.update_root(
                &(FpVar::zero(), FpVar::zero()),
                &(
                    tx.input_nullifiers[j].value.clone(),
                    nullifier_intervals[j].1.clone(),
                ),
                &nullifier_tree_insertion_positions[j],
                &nullifier_tree_insertion_proofs[j],
            )?;
            nullifier_root_old.conditional_enforce_equal(&nullifier_root, &!&is_dummy)?;
            nullifier_root = is_dummy.select(&nullifier_root, &nullifier_root_new)?;
        }

        signer_tree_inclusion_proof
            .verify_membership(
                &(),
                &plasma_blind_config_var.signer_tree_n_to_one_config,
                &signer_root,
                &pk,
            )?
            .enforce_equal(&Boolean::constant(true))?;

        (&next_tx_index - tx_index - FpVar::one()).to_n_bits_le(64)?;

        Ok((
            AggregatorCircuitStateVar {
                V: VV,
                cf_U: cf_UU,
                tx_index: next_tx_index,
                tx_root,
                nullifier_root,
                signer_root,
                block_root,
            },
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
    use sonobe_fs::FoldingSchemeVerifier;
    use std::collections::{BTreeMap, HashMap};

    use ark_bn254::{Fr, G1Projective as C1};
    use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_relations::gr1cs::ConstraintSynthesizer;
    use ark_std::{
        error::Error,
        rand::{Rng, rngs::ThreadRng, thread_rng},
        sync::Arc,
        test_rng,
    };
    use plasmablind_core::{
        circuit::TransactionValidityCircuit,
        datastructures::{
            block::BlockMetadata,
            blocktree::{BLOCK_TREE_ARITY, BlockTree, SparseNAryBlockTree},
            shieldedtx::UTXOTree,
            signerlist::{SIGNER_TREE_ARITY, SignerTree, SparseNArySignerTree},
            transparenttx::TransparentTransaction,
            txtree::{SparseNAryTransactionTree, TRANSACTION_TREE_ARITY, TransactionTree},
            utxo::{UTXO, UTXOInfo, proof::UTXOProof},
        },
        primitives::crh::{
            BlockTreeCRH, BlockTreeCRHGriffin, IntervalCRH, UTXOCRH,
            utils::{
                initialize_griffin_config, initialize_n_to_one_config_griffin,
                initialize_poseidon_config, initialize_two_to_one_binary_tree_poseidon_config,
            },
        },
    };
    use sonobe_fs::{
        FoldingSchemeDecider, FoldingSchemeKeyGenerator, FoldingSchemeOps,
        FoldingSchemePreprocessor, FoldingSchemeProver, nova::Nova, ova::CycleFoldOva,
    };
    use sonobe_ivc::{
        IVC, IVCStatefulProver,
        compilers::cyclefold::{CycleFoldBasedIVC, circuits::CycleFoldCircuit},
    };
    use sonobe_primitives::{
        arithmetizations::r1cs::R1CS,
        circuits::{
            AssignmentsOwned, ConstraintSystemBuilder,
            utils::{CircuitForTest, satisfying_assignments_for_test},
        },
        commitments::pedersen::Pedersen,
        traits::CF1,
        transcripts::griffin::{GriffinParams, sponge::GriffinSponge},
    };

    use crate::Aggregator;

    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        type FS1 = Nova<Pedersen<C1, true>>;
        type FS2 = CycleFoldOva<Pedersen<C2, true>>;
        type T = GriffinSponge<Fr>;

        let mut rng = thread_rng();

        let mut rng1 = test_rng();

        // initialize our plasma blind config
        // poseidon crh only for now, should be configurable in the future
        let two_to_one_poseidon_config = initialize_two_to_one_binary_tree_poseidon_config::<Fr>();
        let poseidon_config = initialize_poseidon_config::<Fr>();
        let griffin_config = initialize_griffin_config::<Fr>();

        let utxo_crh_config = UTXOCRH::setup(&mut rng).unwrap();
        let shielded_tx_leaf_config = ();
        let tx_tree_leaf_config = ();
        let signer_tree_leaf_config = ();
        let nullifier_tree_leaf_config = IntervalCRH::setup(&mut rng).unwrap();
        let block_tree_leaf_config = BlockTreeCRHGriffin::setup(&mut rng).unwrap();

        let shielded_tx_two_to_one_config = two_to_one_poseidon_config.clone();
        let nullifier_tree_two_to_one_config = two_to_one_poseidon_config.clone();
        let block_tree_n_to_one_config =
            initialize_n_to_one_config_griffin::<BLOCK_TREE_ARITY, Fr>();
        let tx_tree_n_to_one_config =
            initialize_n_to_one_config_griffin::<TRANSACTION_TREE_ARITY, Fr>();
        let signer_tree_n_to_one_config =
            initialize_n_to_one_config_griffin::<SIGNER_TREE_ARITY, Fr>();

        let config = PlasmaBlindConfig::new(
            poseidon_config.clone(),
            griffin_config.clone(),
            utxo_crh_config,
            shielded_tx_leaf_config,
            shielded_tx_two_to_one_config,
            tx_tree_leaf_config,
            tx_tree_n_to_one_config,
            signer_tree_leaf_config,
            signer_tree_n_to_one_config,
            nullifier_tree_leaf_config,
            nullifier_tree_two_to_one_config,
            block_tree_leaf_config.clone(),
            block_tree_n_to_one_config.clone(),
        );

        let user_circuit = TransactionValidityCircuit::new(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            vec![Default::default(); TX_IO_SIZE],
            config.clone(),
        );

        let hash_config = Arc::new(GriffinParams::new(16, 5, 9));

        let pp = CycleFoldBasedIVC::<FS1, FS2, T>::preprocess(
            (1 << 19, (2048, 2048), hash_config.clone()),
            &mut rng1,
        )?;

        let pp_f = FS1::preprocess(1 << 16, &mut rng1)?;

        let cyclefold_circuit =
            CycleFoldCircuit::<<FS1 as FoldingSchemeCycleFoldExt<1, 1>>::CFConfig>::default();

        let cs = ConstraintSystemBuilder::new()
            .with_setup_mode()
            .with_circuit(cyclefold_circuit)
            .synthesize()?;
        let arith2 = R1CS::from(cs);
        let dk2 = FS2::generate_keys(pp.1.clone(), arith2)?;

        let cs = ConstraintSystemBuilder::new()
            .with_setup_mode()
            .with_circuit(user_circuit)
            .synthesize()?;
        let arith1 = R1CS::from(cs);

        let dk1 = FS1::generate_keys(pp_f, arith1)?;

        let circuit = AggregatorCircuit {
            config: config.clone(),
            hash_config: hash_config.clone(),
            pp_hash: Default::default(),
            dk1: dk1.clone(),
            dk2: dk2.clone(),
            _r: PhantomData,
        };
        let (pk, vk) = CycleFoldBasedIVC::<FS1, FS2, T>::generate_keys(pp, &circuit)?;
        let mut aggregator = Aggregator::<FS1, FS2, T>::new(circuit, pk);

        // 1. Define users
        let n_users = 100;
        let user_sks = (0..n_users).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let user_pks = user_sks
            .iter()
            .map(|&sk| CRH::evaluate(&config.poseidon_config, vec![sk]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut user_utxos = BTreeMap::from_iter(user_pks.iter().map(|pk| (*pk, HashMap::new())));

        // 2. build fake block 0
        let mut block_tree = SparseNAryBlockTree::blank(
            &config.block_tree_leaf_config,
            &config.block_tree_n_to_one_config,
            &BlockMetadata::default(),
        )
        .unwrap();

        let block_height = 0;

        let mut transactions = BTreeMap::new();
        let mut signers = BTreeMap::new();

        for sender_index in 0..n_users {
            let should_send = rng.gen_bool(0.5);

            if should_send {
                let mut tx = TransparentTransaction::default();

                for utxo_index in 0..TX_IO_SIZE {
                    let should_include = rng.gen_bool(0.5);
                    if should_include {
                        let receiver_index = rng.gen_range(0..n_users);
                        let amount: u32 = rng.r#gen();
                        let utxo =
                            UTXO::new(user_pks[receiver_index], amount as u64, Fr::rand(&mut rng));
                        tx.set_output(utxo_index, utxo);
                    }
                }

                let shielded_tx = ShieldedTransaction::new(
                    &config.griffin_config,
                    &config.utxo_crh_config,
                    &user_sks[sender_index],
                    &tx,
                )
                .unwrap();

                let utxo_tree = UTXOTree::new(
                    &config.shielded_tx_leaf_config,
                    &config.shielded_tx_two_to_one_config,
                    &BTreeMap::from_iter(
                        shielded_tx.output_utxo_commitments.into_iter().enumerate(),
                    ),
                )
                .unwrap();

                for utxo_index in 0..TX_IO_SIZE {
                    let utxo = tx.outputs[utxo_index];
                    if !utxo.is_dummy {
                        let utxo_info = UTXOInfo {
                            utxo_index,
                            tx_index: transactions.len(),
                            block_height,
                            from: user_pks[sender_index],
                        };
                        let utxo_inclusion_proof =
                            utxo_tree.generate_membership_proof(utxo_index).unwrap();
                        user_utxos
                            .get_mut(&utxo.pk)
                            .unwrap()
                            .insert(utxo, (utxo_info, utxo_inclusion_proof));
                    }
                }

                transactions.insert(transactions.len(), utxo_tree.root());
                signers.insert(signers.len(), user_pks[sender_index]);
            }
        }

        let transactions_tree = SparseNAryTransactionTree::new(
            &config.tx_tree_leaf_config,
            &config.tx_tree_n_to_one_config,
            &transactions,
            &Fr::default(),
        )
        .unwrap();

        let signer_tree = SparseNArySignerTree::new(
            &config.signer_tree_leaf_config,
            &config.signer_tree_n_to_one_config,
            &signers,
            &Fr::default(),
        )
        .unwrap();

        let prev_block = BlockMetadata {
            tx_tree_root: transactions_tree.root(),
            signer_tree_root: signer_tree.root(),
            nullifier_tree_root: Fr::default(),
            height: block_height as usize,
        };
        let block_inclusion_proof = {
            block_tree.update(block_height, &prev_block)?;
            block_tree.generate_proof(block_height)?
        };

        assert_eq!(transactions.len(), signers.len());

        let transaction_inclusion_proofs = (0..transactions.len())
            .map(|i| transactions_tree.generate_proof(i))
            .collect::<Result<Vec<_>, _>>()?;
        let signer_inclusion_proofs = (0..signers.len())
            .map(|i| signer_tree.generate_proof(i))
            .collect::<Result<Vec<_>, _>>()?;

        // 3. real block 1
        let mut transactions = vec![];
        let mut senders = vec![];
        let mut assignments_vec = vec![];

        for sender_index in 0..n_users {
            let should_send = rng.gen_bool(0.5);

            if should_send {
                let owned_utxos = user_utxos[&user_pks[sender_index]]
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>();

                if owned_utxos.len() > 0 {
                    let mut tx = TransparentTransaction::default();

                    let mut input_utxos_proofs = vec![UTXOProof::default(); 4];

                    for utxo_index in 0..TX_IO_SIZE.min(owned_utxos.len()) {
                        let should_include = rng.gen_bool(0.5);
                        if should_include {
                            let utxo = owned_utxos[utxo_index];
                            let (info, proof) = user_utxos
                                .get_mut(&user_pks[sender_index])
                                .unwrap()
                                .remove(&utxo)
                                .unwrap();
                            tx.set_input(utxo_index, utxo, info);
                            input_utxos_proofs[utxo_index] = UTXOProof::new(
                                prev_block.clone(),
                                proof,
                                signer_inclusion_proofs[info.tx_index].clone(),
                                transaction_inclusion_proofs[info.tx_index].clone(),
                                block_inclusion_proof.clone(),
                            );
                        }
                    }

                    let amount = tx.inputs.iter().map(|i| i.amount).sum::<u64>();

                    let amount1 = rng.gen_range(0..=amount);
                    let amount2 = amount - amount1;

                    let receiver_index1 = rng.gen_range(0..n_users);
                    let receiver_index2 = rng.gen_range(0..n_users);

                    tx.set_output(
                        3,
                        UTXO::new(user_pks[receiver_index1], amount1, Fr::rand(&mut rng)),
                    );
                    tx.set_output(
                        1,
                        UTXO::new(user_pks[receiver_index2], amount2, Fr::rand(&mut rng)),
                    );

                    let shielded_tx = ShieldedTransaction::new(
                        &config.griffin_config,
                        &config.utxo_crh_config,
                        &user_sks[sender_index],
                        &tx,
                    )
                    .unwrap();

                    let cs = ConstraintSystem::new_ref();
                    TransactionValidityCircuit::new(
                        user_sks[sender_index],
                        user_pks[sender_index],
                        tx,
                        shielded_tx.clone(),
                        block_tree.root(),
                        input_utxos_proofs,
                        config.clone(),
                    )
                    .generate_constraints(cs.clone())
                    .unwrap();
                    assert!(cs.is_satisfied().unwrap());

                    assignments_vec.push(cs.assignments().unwrap());
                    senders.push(user_pks[sender_index]);
                    transactions.push(shielded_tx);
                }
            }
        }

        aggregator.process_transactions(senders, transactions);

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
            proofs.push(Some((WW, U, u, proof)));
        }

        let (i, initial_state, current_state, current_proof, Y, cf_W) =
            aggregator.process_transaction_validity_proofs(proofs, block_tree.root());

        CycleFoldBasedIVC::<FS1, FS2, T>::verify::<AggregatorCircuit<T, FS1, FS2, ThreadRng>>(
            &vk,
            i,
            &initial_state,
            &current_state,
            &current_proof,
        )
        .unwrap();

        FS1::decide_running(&dk1, &Y, &current_state.V).unwrap();
        FS2::decide_running(&dk2, &cf_W, &current_state.cf_U).unwrap();
        Ok(())
    }
}

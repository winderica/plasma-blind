use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::sponge::Absorb;
use ark_relations::gr1cs::ConstraintSystem;
use plasmablind_core::primitives::accumulator::constraints::Accumulator;
use sonobe_fs::{
    FoldingSchemeGadgetOpsFull, FoldingSchemeGadgetOpsPartial, GroupBasedFoldingSchemeSecondary,
};
use sonobe_ivc::compilers::cyclefold::{CycleFoldBasedIVC, FoldingSchemeCycleFoldExt};
use sonobe_ivc::{IVCStatefulProver, IVC};
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::commitments::VectorCommitmentDef;
use sonobe_primitives::traits::{SonobeCurve, CF1};
use sonobe_primitives::transcripts::Transcript;

use crate::circuits::circuit::BalanceCircuit;

pub struct Client<
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
            Arith: From<ConstraintSystem<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeGadgetOpsPartial<1, 1, VerifierKey = ()>,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
        1,
        1,
        Arith: From<ConstraintSystem<CF1<<FS2::VC as VectorCommitmentDef>::Commitment>>>,
        PublicParam: Clone,
        Gadget: FoldingSchemeGadgetOpsFull<1, 1, VerifierKey = ()>,
        VC: VectorCommitmentDef<
            Commitment: SonobeCurve<
                BaseField = <FS1::VC as VectorCommitmentDef>::Scalar,
                ScalarField: Absorb,
            >,
        >,
    >,
    T: Transcript<CF1<<FS1::VC as VectorCommitmentDef>::Commitment>>,
    H: TwoToOneCRHScheme,
    HG: TwoToOneCRHSchemeGadget<H, FS1::TranscriptField>,
    A: Accumulator<FS1::TranscriptField, H, HG>,
> {
    pub pk: <CycleFoldBasedIVC<FS1, FS2, T> as IVC>::ProverKey<BalanceCircuit<FS1, H, HG, A>>,
    pub i: usize,
    pub initial_state: <BalanceCircuit<FS1, H, HG, A> as FCircuit>::State,
    pub current_state: <BalanceCircuit<FS1, H, HG, A> as FCircuit>::State,
    pub current_proof:
        <CycleFoldBasedIVC<FS1, FS2, T> as IVC>::Proof<BalanceCircuit<FS1, H, HG, A>>,
}

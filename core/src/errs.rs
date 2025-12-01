use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlasmaBlindError {
    #[error("{0}")]
    CommitmentError(#[from] sonobe_primitives::commitments::Error),
    #[error("Not same length, right is {0} and left is {1}")]
    NotSameLength(usize, usize),
}

use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},


    #[error("Invalid Instruction")]
    InvalidInstruction {},
    #[error("Admin Already Initialized")]
    AdminAlreadyInitialized {},
    #[error("Invalid Admin Storage Account")]
    InvalidAdminStorage {},
    #[error("Invalid Admin Account")]
    InvalidAdminAccount {},
    #[error("Not Rent Exempt")]
    NotRentExempt {},
    #[error("admin Restricted")]
    AdminRestricted {},
    #[error("Missing Admin Signature")]
    MissingAdminSignature {},
    #[error("Invalid Group Account Owner")]
    InvalidGroupAccountOwner {},
    #[error("Large Public key X")]
    LargePubkeyX {},
    #[error("No Zero Inputs Allowed")]
    ZeroSignatureData {},
    #[error("Not Verified")]
    NotVerified {},


    #[error("Custom Error val: {val:?}")]
    CustomError { val: String },
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

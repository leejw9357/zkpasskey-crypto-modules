use thiserror::Error;

use crate::core::anchor::error::AnchorServiceError;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoServiceError {
    #[error("Anchor service error: {0}")]
    AnchorServiceError(#[from] AnchorServiceError),
}
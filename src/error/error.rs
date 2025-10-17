use thiserror::Error;

use crate::core::anchor::error::AnchorServiceError;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("Core service error: {0}")]
    CoreServiceError(#[from] CryptoServiceError),

    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),

    #[error("Invalid variant")]
    InvalidVariant,

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error("Environment variable error: {0}")]
    EnvVarNotFound(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoServiceError {
    #[error("Anchor service error: {0}")]
    AnchorServiceError(#[from] AnchorServiceError),

    #[error("Schnorr service error: {0}")]
    SchnorrServiceError(#[from] SchnorrServiceError),
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("파일 I/O 에러: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] ark_serialize::SerializationError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchnorrServiceError {
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),

    #[error("Invalid secret key format: {0}")]
    InvalidSecretKeyFormat(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
}

impl From<AnchorServiceError> for ApplicationError {
    fn from(error: AnchorServiceError) -> Self {
        let crypto_error = CryptoServiceError::from(error);

        ApplicationError::from(crypto_error)
    }
}

impl From<SchnorrServiceError> for ApplicationError {
    fn from(error: SchnorrServiceError) -> Self {
        let crypto_error = CryptoServiceError::from(error);

        ApplicationError::from(crypto_error)
    }
}
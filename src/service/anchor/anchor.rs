use std::path::PathBuf;

use ark_std::rand::rngs::OsRng;
use common::{
    codec::point::ToDecimalStr,
    gadget::{anchor::poseidon::PoseidonAnchorSecret, hashes::poseidon::get_poseidon_params},
};
use common_gadget::anchor::dl::DLAnchorSecret;

use crate::{
    core::anchor::{AnchorService, dl::DLAnchorService, poseidon::PoseidonAnchorService},
    error::error::ApplicationError,
    interface::anchor::{DLAnchorKeyExtension, PoseidonAnchorKeyExtension, SecretDto},
    service::{
        anchor::utils::{
            AppDLAnchor, AppPoseidonAnchor, ConcatenateSecrets, DLSecretGenerator, MessageToHashes,
            SecretGenerator,
        },
        constants::{AppCurve, AppField, PoseidonHash},
        key::{anchor::KEY_MANAGER, io::save_key_uncompressed, manager::KeyHandle},
    },
    utils::padding::calculate_fitted_lengths,
};

pub fn generate_and_write_poseidon_anchor_key(
    n: usize,
    k: usize,
    max_aud_len: Option<usize>,
    max_iss_len: Option<usize>,
    max_sub_len: usize,
    out_path: String,
) -> Result<(), ApplicationError> {
    let mut rng = OsRng;

    let key: PoseidonAnchorKeyExtension<AppField> =
        PoseidonAnchorService::setup(&mut rng, n, k, max_aud_len, max_iss_len, max_sub_len)?;

    let path = PathBuf::from(out_path);
    save_key_uncompressed(&path, &key)?;

    Ok(())
}

pub fn generate_and_write_dl_anchor_key(
    n: usize,
    k: usize,
    max_aud_len: Option<usize>,
    max_iss_len: Option<usize>,
    max_sub_len: usize,
    out_path: String,
) -> Result<(), ApplicationError> {
    let mut rng = OsRng;

    let key: DLAnchorKeyExtension<AppCurve> =
        DLAnchorService::setup(&mut rng, n, k, max_aud_len, max_iss_len, max_sub_len)?;

    let path = PathBuf::from(out_path);
    save_key_uncompressed(&path, &key)?;

    Ok(())
}

pub fn create_poseidon_anchor(
    handle_raw: u64,
    secrets: Vec<SecretDto>,
) -> Result<Vec<String>, ApplicationError> {
    let handle = KeyHandle(handle_raw);

    let anchor_key_arc = KEY_MANAGER.get_typed::<PoseidonAnchorKeyExtension<AppField>>(handle)?;

    let hashed_message = derive_hashed_message(
        &secrets,
        anchor_key_arc.max_aud_len,
        anchor_key_arc.max_iss_len,
        anchor_key_arc.max_sub_len,
    )?;

    let anchor_secret: PoseidonAnchorSecret<AppField> = hashed_message.into();
    let anchor = PoseidonAnchorService::anchor(&anchor_key_arc, &anchor_secret)?;

    let out = anchor
        .0
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();

    Ok(out)
}

pub fn create_dl_anchor(
    handle_raw: u64,
    secrets: Vec<SecretDto>,
) -> Result<Vec<String>, ApplicationError> {
    let handle = KeyHandle(handle_raw);

    let anchor_key_arc = KEY_MANAGER.get_typed::<DLAnchorKeyExtension<AppCurve>>(handle)?;

    let hashed_message = derive_hashed_message(
        &secrets,
        anchor_key_arc.max_aud_len,
        anchor_key_arc.max_iss_len,
        anchor_key_arc.max_sub_len,
    )?;

    let (anchor_secret, _): (DLAnchorSecret<AppCurve>, _) =
        DLSecretGenerator::<AppCurve>::generate_secrets(hashed_message)?;

    let anchor = DLAnchorService::anchor(&anchor_key_arc, &anchor_secret)?;

    let out = anchor
        .0
        .iter()
        .flat_map(|p| p.to_decimal_str())
        .collect::<Vec<String>>();

    Ok(out)
}

pub fn poseidon_derive_indices(
    handle_raw: u64,
    anchor: Vec<String>,
    known_secrets: Vec<SecretDto>,
) -> Result<Vec<u8>, ApplicationError> {
    let handle = KeyHandle(handle_raw);

    let anchor_key_arc = KEY_MANAGER.get_typed::<PoseidonAnchorKeyExtension<AppField>>(handle)?;

    let expected_len = anchor_key_arc.n + anchor_key_arc.k - 1;
    if expected_len != anchor.len() {
        return Err(ApplicationError::InvalidFormat(format!(
            "Anchor length must be {} (n + k - 1), got {}",
            expected_len,
            anchor.len()
        )));
    }

    let anchor_val = AppPoseidonAnchor::try_from(anchor)?.0;

    let hashed_message = derive_hashed_message(
        &known_secrets,
        anchor_key_arc.max_aud_len,
        anchor_key_arc.max_iss_len,
        anchor_key_arc.max_sub_len,
    )?;

    let known_secrets_struct: PoseidonAnchorSecret<AppField> = hashed_message.into();

    let indices = PoseidonAnchorService::derive_secret_indices(
        &anchor_key_arc,
        &anchor_val,
        &known_secrets_struct,
    )?;

    Ok(indices.into_iter().map(|i| i as u8).collect())
}

pub fn dl_derive_indices(
    handle_raw: u64,
    anchor: Vec<String>,
    known_secrets: Vec<SecretDto>,
) -> Result<Vec<u8>, ApplicationError> {
    let handle = KeyHandle(handle_raw);

    let anchor_key_arc = KEY_MANAGER.get_typed::<DLAnchorKeyExtension<AppCurve>>(handle)?;

    let expected_len = (anchor_key_arc.n + anchor_key_arc.k - 1) * 2;
    if expected_len != anchor.len() {
        return Err(ApplicationError::InvalidFormat(format!(
            "Anchor length must be {} ((n + k - 1) * 2), got {}",
            expected_len,
            anchor.len()
        )));
    }

    let anchor_val = AppDLAnchor::try_from(anchor)?.0;

    let hashed_message = derive_hashed_message(
        &known_secrets,
        anchor_key_arc.max_aud_len,
        anchor_key_arc.max_iss_len,
        anchor_key_arc.max_sub_len,
    )?;

    let (known_secrets_struct, _rand): (DLAnchorSecret<AppCurve>, _) =
        DLSecretGenerator::<AppCurve>::generate_secrets(hashed_message)?;

    let indices = DLAnchorService::derive_secret_indices(
        &anchor_key_arc,
        &anchor_val,
        &known_secrets_struct,
    )?;

    Ok(indices.into_iter().map(|i| i as u8).collect())
}

fn derive_hashed_message(
    secrets: &[SecretDto],
    max_aud_len: Option<usize>,
    max_iss_len: Option<usize>,
    max_sub_len: usize,
) -> Result<Vec<AppField>, ApplicationError> {
    let (fit_aud, fit_iss, fit_sub) =
        calculate_fitted_lengths::<AppField>(max_aud_len, max_iss_len, max_sub_len);

    let concatenated = secrets.concatenate((fit_aud, fit_iss, fit_sub), '0')?;

    let params = get_poseidon_params::<AppField>();
    let hashed = MessageToHashes::<AppField, PoseidonHash>::to_hashes(&concatenated[..], &params)?;

    Ok(hashed)
}

use ark_ec::CurveGroup;

use common::{
    codec::point::ToDecimalStr,
    gadget::{anchor::poseidon::PoseidonAnchorSecret, hashes::poseidon::get_poseidon_params},
};

use crate::{
    core::anchor::{AnchorService, dl::DLAnchorService, poseidon::PoseidonAnchorService},
    error::error::ApplicationError,
    interface::anchor::{
        AnchorRequestDto, AnchorResponseDto, AnchorType, DLAnchorKeyExtension,
        DeriveSecretIndicesRequestDto, DeriveSecretIndicesResponseDto, PoseidonAnchorKeyExtension,
    },
    service::{
        anchor::utils::{
            AppDLAnchor, AppPoseidonAnchor, ConcatenateSecrets, DLSecretGenerator, MessageToHashes,
            SecretGenerator,
        },
        constants::{AppCurve, AppField, PoseidonHash},
        key::KeyLoadable,
    },
    utils::padding::fit_len_to_field,
};

pub fn create_anchor(dto: AnchorRequestDto) -> Result<AnchorResponseDto, ApplicationError> {
    let variant = dto.variant.parse::<AnchorType>()?;

    let result = match variant {
        AnchorType::Poseidon => handle_poseidon_anchor(&dto),
        AnchorType::DL => handle_dl_anchor(&dto),
    }?;

    Ok(result)
}

pub fn derive_indices(
    dto: DeriveSecretIndicesRequestDto,
) -> Result<DeriveSecretIndicesResponseDto, ApplicationError> {
    let variant = dto.variant.parse::<AnchorType>()?;

    let result = match variant {
        AnchorType::Poseidon => handle_poseidon_derive_indices(&dto),
        AnchorType::DL => handle_dl_derive_indices(&dto),
    }?;

    Ok(result)
}

fn handle_poseidon_anchor(dto: &AnchorRequestDto) -> Result<AnchorResponseDto, ApplicationError> {
    let anchor_key = PoseidonAnchorKeyExtension::<AppField>::from_path(
        dto.anchor_key_path.as_ref(),
        false,
        false,
    )?;

    let max_claim_len = fit_len_to_field::<AppField>(&anchor_key.max_claim_len);

    let concatenated_secrets = dto.secrets.concatenate(max_claim_len, '0')?;

    let poseidon_params = get_poseidon_params::<AppField>();

    let hashed_message = MessageToHashes::<AppField, PoseidonHash>::to_hashes(
        &concatenated_secrets[..],
        &poseidon_params,
    )?;

    let anchor_secret: PoseidonAnchorSecret<AppField> = hashed_message.into();

    let anchor = PoseidonAnchorService::anchor(&anchor_key, &anchor_secret)?;

    let result = anchor
        .0
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();

    Ok(AnchorResponseDto { anchor: result })
}

fn handle_dl_anchor(dto: &AnchorRequestDto) -> Result<AnchorResponseDto, ApplicationError> {
    let anchor_key =
        DLAnchorKeyExtension::<AppCurve>::from_path(dto.anchor_key_path.as_ref(), false, false)?;

    let max_claim_len =
        fit_len_to_field::<<AppCurve as CurveGroup>::BaseField>(&anchor_key.max_claim_len);

    let concatenated_secrets = dto.secrets.concatenate(max_claim_len, '0')?;

    let poseidon_params = get_poseidon_params::<AppField>();

    let hashed_message = MessageToHashes::<AppField, PoseidonHash>::to_hashes(
        &concatenated_secrets[..],
        &poseidon_params,
    )?;

    let (anchor_secret, _) = DLSecretGenerator::<AppCurve>::generate_secrets(hashed_message)?;

    let anchor = DLAnchorService::anchor(&anchor_key, &anchor_secret)?;

    let result = anchor.0.iter().flat_map(|p| p.to_decimal_str()).collect();

    Ok(AnchorResponseDto { anchor: result })
}

fn handle_poseidon_derive_indices(
    dto: &DeriveSecretIndicesRequestDto,
) -> Result<DeriveSecretIndicesResponseDto, ApplicationError> {
    let anchor_key = PoseidonAnchorKeyExtension::<AppField>::from_path(
        dto.anchor_key_path.as_ref(),
        false,
        false,
    )?;

    if (anchor_key.n + anchor_key.k - 1) != dto.anchor.len() {
        return Err(ApplicationError::InvalidFormat(format!(
            "Anchor length must be equal to n + k - 1 = {}",
            anchor_key.n + anchor_key.k - 1
        )));
    }

    let anchor = AppPoseidonAnchor::try_from(dto.anchor.clone())?.0;

    let max_claim_len =
        fit_len_to_field::<<AppCurve as CurveGroup>::BaseField>(&anchor_key.max_claim_len);

    let concatenated_secrets = dto.known_secrets.concatenate(max_claim_len, '0')?;

    let poseidon_params = get_poseidon_params::<AppField>();

    let hashed_message = MessageToHashes::<AppField, PoseidonHash>::to_hashes(
        &concatenated_secrets[..],
        &poseidon_params,
    )?;

    let known_secrets: PoseidonAnchorSecret<AppField> = hashed_message.into();

    let indices =
        PoseidonAnchorService::derive_secret_indices(&anchor_key, &anchor, &known_secrets)?;

    Ok(DeriveSecretIndicesResponseDto {
        indices: indices.into_iter().map(|i| i as u8).collect(),
    })
}

fn handle_dl_derive_indices(
    dto: &DeriveSecretIndicesRequestDto,
) -> Result<DeriveSecretIndicesResponseDto, ApplicationError> {
    let anchor_key =
        DLAnchorKeyExtension::<AppCurve>::from_path(dto.anchor_key_path.as_ref(), false, false)?;

    if ((anchor_key.n + anchor_key.k - 1) * 2) != dto.anchor.len() {
        return Err(ApplicationError::InvalidFormat(format!(
            "Anchor length must be equal to (n + k - 1) * 2 = {}",
            (anchor_key.n + anchor_key.k - 1) * 2
        )));
    }

    let anchor = AppDLAnchor::try_from(dto.anchor.clone())?.0;

    let max_claim_len =
        fit_len_to_field::<<AppCurve as CurveGroup>::BaseField>(&anchor_key.max_claim_len);

    let concatenated_secrets = dto.known_secrets.concatenate(max_claim_len, '0')?;

    let poseidon_params = get_poseidon_params::<AppField>();

    let hashed_message = MessageToHashes::<AppField, PoseidonHash>::to_hashes(
        &concatenated_secrets[..],
        &poseidon_params,
    )?;

    let (known_secrets, _) = DLSecretGenerator::<AppCurve>::generate_secrets(hashed_message)?;

    let indices = DLAnchorService::derive_secret_indices(&anchor_key, &anchor, &known_secrets)?;

    Ok(DeriveSecretIndicesResponseDto {
        indices: indices.into_iter().map(|i| i as u8).collect(),
    })
}

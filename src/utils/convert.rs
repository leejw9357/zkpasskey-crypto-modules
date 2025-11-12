use ark_ff::PrimeField;

use crate::error::error::UtilError;

fn hex_to_bytes_even(s: &str) -> Result<Vec<u8>, UtilError> {
    let mut hex_body = s.strip_prefix("0x").unwrap_or(s).to_owned();
    if hex_body.len() % 2 == 1 {
        hex_body.insert(0, '0'); // 홀수 길이면 앞에 0 하나 패딩
    }
    Ok(hex::decode(&hex_body).map_err(|e| UtilError::ConvertError(e.to_string()))?)
}

/// "0x..."면 hex, 아니면 10진수로 간주하여 F로 변환(모듈러 감싸기)
pub fn str_to_field<F: PrimeField>(s: &str) -> Result<F, UtilError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let bytes = hex_to_bytes_even(s)?;
        Ok(F::from_be_bytes_mod_order(&bytes))
    } else {
        Ok(F::from_str(s)
            .map_err(|_| UtilError::ConvertError(format!("Failed to convert string to field")))?)
    }
}



use ark_ff::PrimeField;

pub fn fit_len_to_field<F: PrimeField>(len: &usize) -> usize {
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = (len + (limb_width - 1)) / limb_width;
    let max_claim_len = n_limbs * limb_width;
    max_claim_len
}

pub fn pad_str<S: Into<String>>(s: S, target_len: usize, pad_char: u8) -> String {
    let s = s.into();
    let len = s.len();
    if len < target_len {
        let mut padded = s;
        padded.push_str(
            &std::iter::repeat(pad_char as char)
                .take(target_len - len)
                .collect::<String>(),
        );
        padded
    } else {
        s
    }
}

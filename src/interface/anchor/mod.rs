use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use common::gadget::anchor::{dl::DLAnchorPublicKey, poseidon::PoseidonAnchorPublicKey};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorKeyExtension<F: PrimeField> {
    pub anchor_key: PoseidonAnchorPublicKey<F>,
    pub n: usize,
    pub k: usize,
    pub max_claim_len: usize,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLAnchorKeyExtension<C: CurveGroup> {
    pub anchor_key: DLAnchorPublicKey<C>,
    pub n: usize,
    pub k: usize,
    pub max_claim_len: usize,
}

pub enum AnchorType {
    DL,
    Poseidon,
}

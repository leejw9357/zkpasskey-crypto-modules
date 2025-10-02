use ark_crypto_primitives::crh::poseidon::CRH;

pub type AppCurve = ark_ed_on_bn254::EdwardsProjective;
pub type AppField = <AppCurve as ark_ec::CurveGroup>::BaseField;
pub type PoseidonHash = CRH<AppField>;
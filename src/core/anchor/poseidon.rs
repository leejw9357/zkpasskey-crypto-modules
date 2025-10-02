use std::marker::PhantomData;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use common::gadget::{
    anchor::{
        AnchorScheme,
        poseidon::{PoseidonAnchor, PoseidonAnchorScheme, PoseidonAnchorSecret},
    },
    matrix::Matrix,
};

use crate::{
    core::anchor::{AnchorParams, AnchorService},
    interface::anchor::PoseidonAnchorKeyExtension,
};

pub struct PoseidonAnchorParams<F: PrimeField + Absorb>(PhantomData<F>);

pub struct PoseidonAnchorService;

impl<F: PrimeField + Absorb> AnchorService<PoseidonAnchorParams<F>> for PoseidonAnchorService {
    fn setup<R: Rng>(
        rng: &mut R,
        n: usize,
        k: usize,
        max_claim_len: usize,
    ) -> Result<
        <PoseidonAnchorParams<F> as AnchorParams>::PublicKey,
        super::error::AnchorServiceError,
    > {
        let anchor_key = PoseidonAnchorScheme::setup(rng, n)?;
        Ok(PoseidonAnchorKeyExtension {
            anchor_key,
            n,
            k,
            max_claim_len,
        })
    }

    fn anchor(
        keys: &<PoseidonAnchorParams<F> as AnchorParams>::PublicKey,
        secret: &<PoseidonAnchorParams<F> as AnchorParams>::Secret,
    ) -> Result<<PoseidonAnchorParams<F> as AnchorParams>::Anchor, super::error::AnchorServiceError>
    {
        let matrix = Matrix::<F>::new(keys.n, keys.k)?;
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&keys.anchor_key, secret, &matrix)?;
        Ok(anchor)
    }

    fn derive_secret_indices(
        anchor_key: &<PoseidonAnchorParams<F> as AnchorParams>::PublicKey,
        anchor: &<PoseidonAnchorParams<F> as AnchorParams>::Anchor,
        known_secrets: &<PoseidonAnchorParams<F> as AnchorParams>::Secret,
    ) -> Result<Vec<usize>, super::error::AnchorServiceError> {
        let matrix = Matrix::<F>::new(anchor_key.n, anchor_key.k)?;
        let indices = PoseidonAnchorScheme::get_indices(
            &anchor_key.anchor_key,
            anchor,
            known_secrets,
            &matrix,
        )?;
        Ok(indices)
    }
}

impl<F: PrimeField + Absorb> AnchorParams for PoseidonAnchorParams<F> {
    type Anchor = PoseidonAnchor<F>;
    type Field = F;
    type PublicKey = PoseidonAnchorKeyExtension<F>;
    type Secret = PoseidonAnchorSecret<F>;
}

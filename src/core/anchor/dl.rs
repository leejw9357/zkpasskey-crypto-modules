use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use common::gadget::{anchor::{
    dl::{DLAnchor, DLAnchorScheme, DLAnchorSecret}, AnchorScheme
}, matrix::Matrix};

use crate::{
    core::anchor::{AnchorParams, AnchorService},
    interface::anchor::DLAnchorKeyExtension,
};

pub struct DLAnchorParams<C: CurveGroup>
where
    C::BaseField: PrimeField,
{
    _marker: PhantomData<C>,
}

pub struct DLAnchorService;

impl<C: CurveGroup> AnchorService<DLAnchorParams<C>> for DLAnchorService
where 
    C::BaseField: PrimeField,
{
    fn setup<R: ark_std::rand::Rng>(
        rng: &mut R,
        n: usize,
        k: usize,
        max_claim_len: usize,
    ) -> Result<
        <DLAnchorParams<C> as super::AnchorParams>::PublicKey,
        super::error::AnchorServiceError,
    > {
        let anchor_key = DLAnchorScheme::setup(rng, n)?;

        Ok(DLAnchorKeyExtension {
            anchor_key,
            n,
            k,
            max_claim_len,
        })
    }

    fn anchor(
        keys: &<DLAnchorParams<C> as super::AnchorParams>::PublicKey,
        secret: &<DLAnchorParams<C> as super::AnchorParams>::Secret,
    ) -> Result<<DLAnchorParams<C> as super::AnchorParams>::Anchor, super::error::AnchorServiceError>
    {
        let matrix = Matrix::<C::ScalarField>::new(keys.n, keys.k)?;
        let anchor = DLAnchorScheme::<C>::generate_anchor(&keys.anchor_key, secret, &matrix)?;
        Ok(anchor)
    }

    fn derive_secret_indices(anchor_key: &<DLAnchorParams<C> as AnchorParams>::PublicKey, anchor: &<DLAnchorParams<C> as AnchorParams>::Anchor, known_secrets: &<DLAnchorParams<C> as AnchorParams>::Secret) -> Result<Vec<usize>, super::error::AnchorServiceError> {
        let matrix = Matrix::<C::ScalarField>::new(anchor_key.n, anchor_key.k)?;
        let indices = DLAnchorScheme::get_indices(&anchor_key.anchor_key, anchor, known_secrets, &matrix)?;
        Ok(indices)
    }
}

impl<C: CurveGroup> AnchorParams for DLAnchorParams<C>
where 
    C::BaseField: PrimeField,
{
    type Anchor = DLAnchor<C>;
    type Field = C::ScalarField;
    type PublicKey = DLAnchorKeyExtension<C>;
    type Secret = DLAnchorSecret<C>;
}

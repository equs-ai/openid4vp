use crate::signer::Signer;
use anyhow::{bail, Error};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "Vec<T>", into = "Vec<T>")]
pub struct NonEmptyVec<T: Clone>(Vec<T>);

impl<T: Clone> NonEmptyVec<T> {
    pub fn new(t: T) -> Self {
        Self(vec![t])
    }

    pub fn maybe_new(v: Vec<T>) -> Option<Self> {
        Self::try_from(v).ok()
    }

    pub fn push(&mut self, t: T) {
        self.0.push(t)
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: Clone> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Error;

    fn try_from(v: Vec<T>) -> Result<NonEmptyVec<T>, Error> {
        if v.is_empty() {
            bail!("cannot create a NonEmptyVec from an empty Vec")
        }
        Ok(NonEmptyVec(v))
    }
}

impl<T: Clone> From<NonEmptyVec<T>> for Vec<T> {
    fn from(NonEmptyVec(v): NonEmptyVec<T>) -> Vec<T> {
        v
    }
}

impl<T: Clone> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Clone> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

pub(crate) fn contains_all<T: PartialEq>(large: &[T], small: &[T]) -> bool {
    small.iter().all(|item| large.contains(item))
}

pub(crate) fn from_string_or_value<T>(value: &serde_json::Value) -> serde_json::Result<T>
where
    T: DeserializeOwned,
{
    match value {
        serde_json::Value::String(ref json_str) => serde_json::from_str(json_str),
        _ => serde_json::from_value(value.clone()),
    }
}

pub async fn generate_jwt<T, S>(
    header: serde_json::Value,
    body: &T,
    signer: &S,
) -> anyhow::Result<String>
where
    S: Signer + ?Sized,
    T: Serialize,
{
    let header_b64: String =
        serde_json::to_vec(&header).map(|b| BASE64_URL_SAFE_NO_PAD.encode(b))?;
    let body_b64 = serde_json::to_vec(body).map(|b| BASE64_URL_SAFE_NO_PAD.encode(b))?;
    let payload = [header_b64.as_bytes(), b".", body_b64.as_bytes()].concat();

    let signature = signer.sign(&payload).await?;
    let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{header_b64}.{body_b64}.{signature_b64}"))
}

use crate::signer::Signer;
use anyhow::{bail, Error};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(try_from = "Vec<T>")]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
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

impl<T> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Error;

    fn try_from(v: Vec<T>) -> Result<NonEmptyVec<T>, Error> {
        if v.is_empty() {
            bail!("cannot create a NonEmptyVec from an empty Vec")
        }
        Ok(NonEmptyVec(v))
    }
}

impl<T> From<NonEmptyVec<T>> for Vec<T> {
    fn from(NonEmptyVec(v): NonEmptyVec<T>) -> Vec<T> {
        v
    }
}

impl<T> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<'a, T> IntoIterator for &'a NonEmptyVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> IntoIterator for NonEmptyVec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Serialize> Serialize for NonEmptyVec<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
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

/// MaybeSend is a marker to determine whether a type is Send or not. We use this trait to wrap the Send requirement for wasm32 target.
#[cfg(not(target_arch = "wasm32"))]
pub trait WasmNotSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> WasmNotSend for T {}

#[cfg(target_arch = "wasm32")]
pub trait WasmNotSend {}
#[cfg(target_arch = "wasm32")]
impl<T> WasmNotSend for T {}

/// MaybeSync is a marker to determine whether a type is Sync or not. We use this trait to wrap the Sync requirement for wasm32 target.
#[cfg(not(target_arch = "wasm32"))]
pub trait WasmNotSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync> WasmNotSync for T {}

#[cfg(target_arch = "wasm32")]
pub trait WasmNotSync {}
#[cfg(target_arch = "wasm32")]
impl<T> WasmNotSync for T {}

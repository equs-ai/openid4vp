use anyhow::Result;
use async_trait::async_trait;

use ssi::jwk::JWK;

use std::fmt::Debug;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Signer: Debug {
    type Error: std::fmt::Display;

    /// The algorithm that will be used to sign.
    fn alg(&self) -> Result<String>;

    /// The public JWK of the signer.
    fn jwk(&self) -> Result<JWK>;

    /// Sign the payload and return the signature.
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

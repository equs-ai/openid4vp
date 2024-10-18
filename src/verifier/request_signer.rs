use anyhow::Result;
use async_trait::async_trait;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

use ssi::jwk::JWK;

use std::fmt::Debug;

#[async_trait]
pub trait RequestSigner: Debug {
    type Error: std::fmt::Display;

    /// The algorithm that will be used to sign.
    fn alg(&self) -> Result<String>;

    /// The public JWK of the signer.
    fn jwk(&self) -> Result<JWK>;

    /// Sign the payload and return the signature.
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Debug)]
pub struct P256Signer {
    key: SigningKey,
    jwk: JWK,
}

impl P256Signer {
    pub fn new(key: SigningKey) -> Result<Self> {
        let pk: p256::PublicKey = key.verifying_key().into();
        let jwk = serde_json::from_str(&pk.to_jwk_string())?;
        Ok(Self { key, jwk })
    }

    pub fn jwk(&self) -> &JWK {
        &self.jwk
    }
}

#[async_trait]
impl RequestSigner for P256Signer {
    type Error = anyhow::Error;

    fn alg(&self) -> Result<String, Self::Error> {
        Ok("ES256".to_string())
    }

    fn jwk(&self) -> Result<JWK, Self::Error> {
        Ok(self.jwk.clone())
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sig: Signature = self.key.sign(payload);
        Ok(sig.to_vec())
    }
}

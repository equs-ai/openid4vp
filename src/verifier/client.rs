use std::{fmt::Debug, sync::Arc};

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use base64::prelude::*;
use p256::ecdsa::signature::digest::Digest;
use serde_json::json;
use ssi::crypto::k256::sha2;
use ssi::jwk::JWKResolver;
use tracing::debug;
use x509_cert::{
    der::Encode,
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::core::authorization_request::parameters::DECENTRALIZED_IDENTIFIER;
use crate::core::authorization_request::{
    parameters::{ClientId, ClientIdScheme},
    AuthorizationRequestObject,
};
use crate::core::util::http::MIME_TYPE_OAUTH_REQ_JWT;
use crate::signer::Signer;
use crate::utils::{generate_jwt, WasmNotSync};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Client: Debug {
    fn id(&self) -> &ClientId;

    fn scheme(&self) -> ClientIdScheme;

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String>;
}

/// A [Client] with the `did` Client Identifier.
#[derive(Debug, Clone)]
pub struct DecentralizedIdentifierClient<S: Signer> {
    id: ClientId,
    vm: String,
    signer: S,
}

impl<S: Signer> DecentralizedIdentifierClient<S> {
    pub async fn new(vm: String, signer: S, resolver: impl JWKResolver) -> Result<Self> {
        let (id, _f) = vm.rsplit_once('#').context(format!(
            "expected a DID verification method, received '{vm}'"
        ))?;

        let jwk = resolver
            .fetch_public_jwk(Some(&vm))
            .await
            .context("unable to resolve key from verification method")?;

        if *jwk != signer.jwk().context("signer did not have a JWK")? {
            bail!(
                "verification method resolved from DID document did not match public key of signer"
            )
        }

        let client_id = format!("{}:{}", DECENTRALIZED_IDENTIFIER, id);
        Ok(Self {
            id: ClientId::new(client_id)?,
            vm,
            signer,
        })
    }
}

/// A [Client] with the `x509_san_dns` or `x509_hash` Client Identifier.
#[derive(Debug, Clone)]
pub struct X509Client {
    id: ClientId,
    x5c: Vec<Certificate>,
    signer: Arc<dyn Signer<Error = anyhow::Error> + Send + Sync>,
    variant: X509Variant,
}

impl X509Client {
    pub fn new(
        x5c: Vec<Certificate>,
        signer: Arc<dyn Signer<Error = anyhow::Error> + Send + Sync>,
        variant: X509Variant,
    ) -> Result<Self> {
        let leaf = &x5c[0];
        let id = if variant == X509Variant::Hash {
            let hash = sha2::Sha256::digest(&leaf.tbs_certificate.to_der()?);
            BASE64_STANDARD_NO_PAD.encode(hash)
        } else {
            let id = if let Some(san) = leaf
                .tbs_certificate
                .filter::<SubjectAltName>()
                .filter_map(|r| match r {
                    Ok((_crit, san)) => Some(san.0.into_iter()),
                    Err(e) => {
                        debug!("unable to parse SubjectAlternativeName from DER: {e}");
                        None
                    }
                })
                .flatten()
                .filter_map(|general_name| match general_name {
                    GeneralName::DnsName(uri) => Some(uri.to_string()),
                    gn => {
                        debug!("found non-DNS SAN: {gn:?}");
                        None
                    }
                })
                .next()
            {
                san
            } else {
                bail!("x509 certificate does not contain Subject Alternative Name");
            };
            id
        };

        let client_id = if variant == X509Variant::Hash {
            format!("x509_hash:{}", id)
        } else {
            format!("x509_san_dns{}", id)
        };
        Ok(X509Client {
            id: ClientId::new(client_id)?,
            x5c,
            signer,
            variant,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum X509Variant {
    Hash,
    SanDns,
}

impl X509Variant {
    pub fn to_scheme(&self) -> ClientIdScheme {
        match self {
            X509Variant::Hash => ClientIdScheme::X509Hash,
            X509Variant::SanDns => ClientIdScheme::X509SanDns,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: Signer + WasmNotSync> Client for DecentralizedIdentifierClient<S> {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn scheme(&self) -> ClientIdScheme {
        ClientIdScheme::DecentralizedIdentifier
    }

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        let algorithm = self
            .signer
            .alg()
            .context("failed to retrieve signing algorithm")?;
        let header = json!({
            "alg": algorithm,
            "kid": self.vm,
            "typ": MIME_TYPE_OAUTH_REQ_JWT
        });
        generate_jwt(header, body, &self.signer).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Client for X509Client {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn scheme(&self) -> ClientIdScheme {
        match self.variant {
            X509Variant::SanDns => ClientIdScheme::X509SanDns,
            X509Variant::Hash => ClientIdScheme::X509Hash,
        }
    }

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        let algorithm = self
            .signer
            .alg()
            .context("failed to retrieve signing algorithm")?;
        let x5c: Vec<String> = self
            .x5c
            .iter()
            .map(|x509| x509.to_der())
            .map(|der| Ok(BASE64_STANDARD.encode(der?)))
            .collect::<Result<_>>()?;
        let header = json!({
            "alg": algorithm,
            "x5c": x5c,
            "typ": "JWT"
        });
        generate_jwt(header, body, self.signer.as_ref()).await
    }
}

/// A [Client] with the `redirect_uri` Client Identifier.
#[derive(Debug, Clone)]
pub struct RedirectUriClient {
    id: ClientId,
}

impl RedirectUriClient {
    pub fn new(id: ClientId) -> Self {
        Self { id }
    }
}
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Client for RedirectUriClient {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn scheme(&self) -> ClientIdScheme {
        ClientIdScheme::RedirectUri
    }

    async fn generate_request_object_jwt(&self, _: &AuthorizationRequestObject) -> Result<String> {
        Err(anyhow!(
            "generation of signed jwt is not supported in 'redirect_uri' client identifier"
        ))
    }
}

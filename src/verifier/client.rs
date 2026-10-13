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

use crate::core::authorization_request::parameters::{DECENTRALIZED_IDENTIFIER, REDIRECT_URI};
use crate::core::authorization_request::{
    parameters::{ClientId, ClientIdPrefix},
    AuthorizationRequestObject,
};
use crate::core::util::http::MIME_TYPE_OAUTH_REQ_JWT_SHORT;
use crate::signer::Signer;
use crate::utils::{generate_jwt, WasmNotSync};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Client: Debug {
    fn id(&self) -> &ClientId;

    fn prefix(&self) -> ClientIdPrefix;

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
        let id = Self::client_id(&x5c, variant)?;

        Ok(X509Client {
            id,
            x5c,
            signer,
            variant,
        })
    }

    /// Derives the [ClientId] the leaf of `x5c` implies — the leaf's hash for
    /// [X509Variant::Hash], its Subject Alternative Name for
    /// [X509Variant::SanDns].
    ///
    /// Takes no [Signer]: deriving an identifier never signs anything. Callers
    /// that only need to know which `client_id` a chain yields — an `x509_hash`
    /// one cannot be written by hand, so this is the only way to learn it —
    /// should use this rather than building a whole [X509Client] around a
    /// placeholder signer. [X509Client::new] calls it, so the two cannot drift.
    ///
    /// # Errors
    ///
    /// If `x5c` is empty, the leaf cannot be DER-encoded, or (for
    /// [X509Variant::SanDns]) the leaf carries no DNS Subject Alternative Name.
    pub fn client_id(x5c: &[Certificate], variant: X509Variant) -> Result<ClientId> {
        let leaf = x5c
            .first()
            .ok_or_else(|| anyhow!("x509 certificate chain is empty"))?;

        let id = match variant {
            X509Variant::Hash => {
                let hash = sha2::Sha256::digest(&leaf.to_der()?);
                BASE64_URL_SAFE_NO_PAD.encode(hash)
            }
            X509Variant::SanDns => leaf
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
                .ok_or_else(|| {
                    anyhow!("x509 certificate does not contain Subject Alternative Name")
                })?,
        };

        ClientId::new(format!("{}:{}", variant.to_prefix(), id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum X509Variant {
    Hash,
    SanDns,
}

impl X509Variant {
    pub fn to_prefix(&self) -> ClientIdPrefix {
        match self {
            X509Variant::Hash => ClientIdPrefix::X509Hash,
            X509Variant::SanDns => ClientIdPrefix::X509SanDns,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: Signer + WasmNotSync> Client for DecentralizedIdentifierClient<S> {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn prefix(&self) -> ClientIdPrefix {
        ClientIdPrefix::DecentralizedIdentifier
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
            "typ": MIME_TYPE_OAUTH_REQ_JWT_SHORT
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

    fn prefix(&self) -> ClientIdPrefix {
        match self.variant {
            X509Variant::SanDns => ClientIdPrefix::X509SanDns,
            X509Variant::Hash => ClientIdPrefix::X509Hash,
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
            "typ": MIME_TYPE_OAUTH_REQ_JWT_SHORT
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
    pub fn new(id: String) -> Result<Self> {
        let client_id = format!("{}:{}", REDIRECT_URI, id);
        Ok(Self {
            id: ClientId::new(client_id)?,
        })
    }
}
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Client for RedirectUriClient {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn prefix(&self) -> ClientIdPrefix {
        ClientIdPrefix::RedirectUri
    }

    async fn generate_request_object_jwt(&self, _: &AuthorizationRequestObject) -> Result<String> {
        Err(anyhow!(
            "generation of signed jwt is not supported in 'redirect_uri' client identifier"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::DecodePem;

    /// P-256 leaf with `subjectAltName = DNS:verifier.example`.
    const LEAF_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIUZ0sUbVcHoWEWaz9DcIw3HNDv4mwwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQdmVyaWZpZXIuZXhhbXBsZTAeFw0yNjA3MjUxMzE3NTJaFw0z
NjA3MjIxMzE3NTJaMBsxGTAXBgNVBAMMEHZlcmlmaWVyLmV4YW1wbGUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQfGeYeCA4RI9xmfml8yuB289vgYdplBUPDtlkR
VX5n8ec6c150wgvBJD5etexGbiSrJtlZ5VKI2IuCo3eMlCgpo20wazAdBgNVHQ4E
FgQU9uFMq/NqtsYpwU5bdoAAMmCgYGQwHwYDVR0jBBgwFoAU9uFMq/NqtsYpwU5b
doAAMmCgYGQwGwYDVR0RBBQwEoIQdmVyaWZpZXIuZXhhbXBsZTAMBgNVHRMBAf8E
AjAAMAoGCCqGSM49BAMCA0gAMEUCIQDm4xtRVAZeLVpXtBF+JmZA6G1EgT3hJoLM
olfQxZzr/AIgN0aICEuoH4qkiU5n6zsYrRUGSjxg74hGubPQcUI901Y=
-----END CERTIFICATE-----";

    #[derive(Debug)]
    struct NoSigner;

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl Signer for NoSigner {
        type Error = anyhow::Error;

        fn alg(&self) -> Result<String> {
            unimplemented!("'alg' is not implemented for NoSigner")
        }

        fn jwk(&self) -> Result<ssi::jwk::JWK> {
            unimplemented!("'jwk' is not implemented for NoSigner")
        }

        async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>> {
            unimplemented!("'sign' is not implemented for NoSigner")
        }
    }

    fn client(variant: X509Variant) -> X509Client {
        let leaf = Certificate::from_pem(LEAF_PEM).expect("leaf certificate parses");
        X509Client::new(vec![leaf], Arc::new(NoSigner), variant).expect("client is constructed")
    }

    #[test]
    fn x509_hash_client_id_is_base64url_sha256_of_the_whole_der_certificate() {
        assert_eq!(
            client(X509Variant::Hash).id().to_string(),
            "x509_hash:IKC0DWzNRPtrEnSH-5lUfjr2qo2Jicub4x9z32rk_9Y"
        );
    }

    #[test]
    fn x509_san_dns_client_id_is_the_leaf_dns_san() {
        assert_eq!(
            client(X509Variant::SanDns).id().to_string(),
            "x509_san_dns:verifier.example"
        );
    }

    #[rstest::rstest]
    #[case(X509Variant::Hash)]
    #[case(X509Variant::SanDns)]
    fn client_id_needs_no_signer_and_agrees_with_the_built_client(#[case] variant: X509Variant) {
        let leaf = Certificate::from_pem(LEAF_PEM).expect("leaf certificate parses");

        let derived = X509Client::client_id(&[leaf], variant).expect("client_id is derived");

        assert_eq!(&derived, client(variant).id());
    }

    /// Used to index `x5c[0]` unconditionally and panic.
    #[rstest::rstest]
    #[case(X509Variant::Hash)]
    #[case(X509Variant::SanDns)]
    fn client_id_on_an_empty_chain_errors(#[case] variant: X509Variant) {
        let err = X509Client::client_id(&[], variant).expect_err("an empty chain has no leaf");

        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn new_on_an_empty_chain_errors() {
        let err = X509Client::new(vec![], Arc::new(NoSigner), X509Variant::SanDns)
            .expect_err("an empty chain has no leaf");

        assert!(err.to_string().contains("empty"), "unexpected error: {err}");
    }
}

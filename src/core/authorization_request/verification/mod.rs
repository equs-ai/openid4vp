use super::{
    parameters::{ClientIdScheme, ClientMetadata, ResponseMode},
    AuthorizationRequestObject, FetchedAuthorizationRequest,
};
use crate::core::authorization_request::parameters::ClientId;
use crate::core::error::Error;
use crate::core::{
    metadata::parameters::{
        verifier::{AuthorizationEncryptedResponseAlg, AuthorizationEncryptedResponseEnc},
        wallet::{
            AuthorizationEncryptionAlgValuesSupported, AuthorizationEncryptionEncValuesSupported,
            ClientIdSchemesSupported,
        },
    },
    object::{ParsingErrorContext, TypedParameter, UntypedObject},
};
use crate::wallet::Wallet;
use anyhow::Result;
use async_trait::async_trait;
use oauth2::{HttpRequest, HttpResponse};
use std::future::Future;
use url::Url;

pub mod did;
pub mod verifier;
pub mod x509_san;

/// Verifies Authorization Request Objects.
#[allow(unused_variables)]
#[async_trait]
pub trait RequestVerifier {
    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `did`.
    ///
    /// See default implementation [did].
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'did' client verification is not supported"))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `entity_id`.
    async fn entity_id(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'entity_id' client verification is not supported"))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `pre-registered`.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'preregistered' client verification is not supported"))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `redirect_uri`.
    ///
    /// See default implementation [redirect_uri].
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        redirect_uri: &Url,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'redirect_uri' client verification is not supported"))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `verifier_attestation`.
    async fn verifier_attestation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'verifier_attestation' client verification is not supported"))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_dns`.
    ///
    /// See default implementation [x509_san_uri].
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'x509_san_dns' client verification is not supported"))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_uri`.
    ///
    /// See default implementation [x509_san_uri].
    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'x509_san_uri' client verification is not supported"))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is any other value.
    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        Err(Error::protocol_access_denied("'other' client verification is not supported"))
    }
}

pub(crate) async fn verify_request<W, HC, F, RE>(
    wallet: &W,
    fetched_request: FetchedAuthorizationRequest,
    http_client_fn: HC,
) -> Result<AuthorizationRequestObject, Error>
where
    W: Wallet + ?Sized,
    HC: Fn(HttpRequest) -> F + Send,
    F: Future<Output = Result<HttpResponse, RE>> + Send,
    RE: std::error::Error + 'static + Sync + Send,
{
    let request = match fetched_request {
        FetchedAuthorizationRequest::Plain(request) => {
            wallet.redirect_uri(&request, request.return_uri()).await?;
            request
        }
        FetchedAuthorizationRequest::UnverifiedJwt(jwt) => {
            let request: AuthorizationRequestObject =
                ssi::jwt::decode_unverified::<UntypedObject>(&jwt)
                    .map_err(|e| {
                        Error::protocol_invalid_req(
                            "unable to decode Authorization Request Object JWT",
                        )
                        .add_source(e.into())
                    })?
                    .try_into()?;

            match request.client_id_scheme() {
                ClientIdScheme::Did => wallet.did(&request, jwt).await?,
                ClientIdScheme::EntityId => wallet.entity_id(&request, jwt).await?,
                ClientIdScheme::PreRegistered => wallet.preregistered(&request, jwt).await?,
                ClientIdScheme::VerifierAttestation => wallet.verifier_attestation(&request, jwt).await?,
                ClientIdScheme::X509SanDns => wallet.x509_san_dns(&request, jwt).await?,
                ClientIdScheme::X509SanUri => wallet.x509_san_uri(&request, jwt).await?,
                ClientIdScheme::Other(scheme) => wallet.other(scheme, &request, jwt).await?,
                _ => {}
            };

            request
        }
    };

    validate_request_against_metadata(wallet, &request, http_client_fn).await?;

    Ok(request)
}

pub(crate) async fn validate_request_against_metadata<W, HC, F, RE>(
    wallet: &W,
    request: &AuthorizationRequestObject,
    http_client_fn: HC,
) -> Result<(), Error>
where
    W: Wallet + ?Sized,
    HC: Fn(HttpRequest) -> F,
    F: Future<Output = Result<HttpResponse, RE>>,
    RE: std::error::Error + 'static + Sync + Send,
{
    let wallet_metadata = wallet.metadata();

    let client_id_scheme = request.client_id_scheme();
    if !wallet_metadata
        .get_or_default::<ClientIdSchemesSupported>()?
        .0
        .contains(client_id_scheme)
    {
        return Err(Error::protocol_invalid_req(&format!(
            "wallet does not support client_id_scheme '{}'",
            client_id_scheme
        )));
    }

    let client_metadata = ClientMetadata::resolve(request, http_client_fn).await?.0;

    let response_mode = request.get::<ResponseMode>().parsing_error()?;

    if response_mode.is_jarm()? {
        let alg = client_metadata
            .get::<AuthorizationEncryptedResponseAlg>()
            .parsing_error()?;
        let enc = client_metadata
            .get::<AuthorizationEncryptedResponseEnc>()
            .parsing_error()?;

        if let Some(supported_algs) =
            wallet_metadata.get::<AuthorizationEncryptionAlgValuesSupported>()
        {
            if !supported_algs?.0.contains(&alg.0) {
                return Err(Error::protocol_invalid_req(&format!(
                    "unsupported {} '{}'",
                    AuthorizationEncryptedResponseAlg::KEY,
                    alg.0
                )));
            }
        }
        if let Some(supported_encs) =
            wallet_metadata.get::<AuthorizationEncryptionEncValuesSupported>()
        {
            if !supported_encs?.0.contains(&enc.0) {
                return Err(Error::protocol_invalid_req(&format!(
                    "unsupported {} '{}'",
                    AuthorizationEncryptedResponseEnc::KEY,
                    enc.0
                )));
            }
        }
    }

    Ok(())
}

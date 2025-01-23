use super::{
    parameters::{ClientIdScheme, ClientMetadata, ResponseMode},
    AuthorizationRequestObject, FetchedAuthorizationRequest,
};
use crate::core::authorization_request::parameters::ResponseType;
use crate::core::error::Error;
use crate::core::metadata::parameters::SubjectSyntaxTypesSupported;
use crate::core::metadata::WalletMetadata;
use crate::core::{
    metadata::parameters::{
        verifier::{AuthorizationEncryptedResponseAlg, AuthorizationEncryptedResponseEnc},
        wallet::{
            AuthorizationEncryptionAlgValuesSupported, AuthorizationEncryptionEncValuesSupported,
            ClientIdSchemesSupported, VpFormatsSupported,
        },
    },
    object::{ParsingErrorContext, TypedParameter, UntypedObject},
};
use crate::wallet::Wallet;
use anyhow::{Context, Result};
use async_trait::async_trait;
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
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'did' client verification is not supported", &state))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `entity_id`.
    async fn entity_id(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'entity_id' client verification is not supported", &state))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `pre-registered`.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'preregistered' client verification is not supported", &state))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `redirect_uri`.
    ///
    /// See default implementation [redirect_uri].
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        redirect_uri: &Url,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'redirect_uri' client verification is not supported", &state))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `verifier_attestation`.
    async fn verifier_attestation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'verifier_attestation' client verification is not supported", &state))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_dns`.
    ///
    /// See default implementation [x509_san_uri].
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'x509_san_dns' client verification is not supported", &state))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `x509_san_uri`.
    ///
    /// See default implementation [x509_san_uri].
    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'x509_san_uri' client verification is not supported", &state))
    }

    /// Performs verification on Authorization Request Objects when `client_id_scheme` is any other value.
    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied("'other' client verification is not supported", &state))
    }
}

pub(crate) async fn verify_request<W>(
    wallet: &W,
    fetched_request: FetchedAuthorizationRequest,
) -> Result<AuthorizationRequestObject, Error>
where
    W: Wallet + ?Sized,
{
    let request = match fetched_request {
        FetchedAuthorizationRequest::Plain(request) => {
            wallet.redirect_uri(&request, request.return_uri()).await?;
            request
        }
        FetchedAuthorizationRequest::UnverifiedJwt(jwt) => {
            let request: AuthorizationRequestObject =
                ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
                    .map_err(|e| {
                        Error::protocol_invalid_req(
                            "unable to decode Authorization Request Object JWT",
                            &None
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

    validate_request_against_metadata(wallet, &request).await?;

    Ok(request)
}

pub(crate) async fn validate_request_against_metadata<W>(
    wallet: &W,
    request: &AuthorizationRequestObject,
) -> Result<(), Error>
where
    W: Wallet + ?Sized,
{
    let state = request.state();
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
        ), &state));
    }

    validate_response_type(request, wallet_metadata)?;

    let client_metadata = ClientMetadata::resolve(request, wallet.http_client()).await?;
    validate_vp_formats(&client_metadata, wallet_metadata, &state)?;

    let response_mode = request.get::<ResponseMode>().parsing_error()?;

    if response_mode.is_jarm()? {
        let alg = client_metadata
            .0
            .get::<AuthorizationEncryptedResponseAlg>()
            .parsing_error()?;
        let enc = client_metadata
            .0
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
                ), &state));
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
                ), &state));
            }
        }
    }

    Ok(())
}

fn validate_response_type(
    authorization_request_object: &AuthorizationRequestObject,
    wallet_metadata: &WalletMetadata,
) -> Result<(), Error> {
    let state = authorization_request_object.state();
    let response_type = authorization_request_object
        .get::<ResponseType>()
        .ok_or_else( || Error::protocol_invalid_req("'response_type' is not declared, it is a required parameter of authorization request object", &state))?
        .context("error occurred when retrieving response type")?;

    if !wallet_metadata
        .response_types_supported()
        .0
        .contains(&response_type)
    {
        return Err(Error::protocol_invalid_req(&format!(
            "response type = '{}' is not supported",
            String::from(response_type)
        ), &state));
    }

    if ResponseType::VpTokenIdToken == response_type {
        let subject_syntax_types_supported = authorization_request_object
            .get::<ClientMetadata>()
            .ok_or_else( || Error::protocol_invalid_req("'client_metadata' is required when response type is 'vp_token id_token'", &state))?
            .context("error occurred when retrieving 'client_metadata'")?
            .0.get::<SubjectSyntaxTypesSupported>()
            .ok_or_else(|| Error::protocol_invalid_req("'subject_syntax_types_supported' is required when response type is 'vp_token id_token'", &state))?
            .context("error occurred when retrieving 'subject_syntax_types_supported'")?;

        let unsupported = subject_syntax_types_supported.0.iter().find(|s| {
            !wallet_metadata
                .subject_syntax_types_supported()
                .contains(&s)
        });

        if let Some(unsupported) = unsupported {
            return Err(Error::protocol_invalid_req(&format!(
                "subject syntax type = '{unsupported}' is not supported"
            ), &state));
        }
    }

    Ok(())
}

fn validate_vp_formats(
    metadata: &ClientMetadata,
    wallet_metadata: &WalletMetadata,
    state: &Option<String>
) -> Result<(), Error> {
    let Ok(vp_formats) = metadata.0.get::<VpFormatsSupported>().parsing_error() else {
        return Ok(());
    };

    for (format, alg) in vp_formats.0 {
        let found = wallet_metadata
            .vp_formats_supported()
            .contains_claim_format_with_payload(&format, &alg);

        if !found {
            return Err(Error::protocol_vp_formats_not_supported(&format!(
                "unsupported vp format = '{}' with alg values '{}'",
                String::from(format.to_owned()),
                serde_json::to_string(&alg).unwrap_or_else(|_| "".to_string())
            ), state));
        }
    }

    Ok(())
}

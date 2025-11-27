use super::{
    parameters::{ClientIdPrefix, ClientMetadata},
    AuthorizationRequestObject, FetchedAuthorizationRequest,
};
use crate::core::authorization_request::parameters::{ResponseMode, ResponseType};
use crate::core::error::{Error, ErrorType};
use crate::core::metadata::parameters::{SubjectSyntaxTypesSupported, VpFormatsSupported};
use crate::core::metadata::WalletMetadata;
use crate::core::{
    metadata::parameters::wallet::ClientIdPrefixesSupported,
    object::{ParsingErrorContext, UntypedObject},
};
use crate::wallet::Wallet;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use ssi::claims::jws::{decode_jws_parts, split_jws};
use url::Url;

pub mod did;
pub mod verifier;
pub mod x509_san;

/// Verifies Authorization Request Objects.
#[allow(unused_variables)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait RequestVerifier {
    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `decentralized_identifier`.
    ///
    /// See default implementation [decentralized_identifier].
    async fn decentralized_identifier(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'decentralized_identifier' client verification is not supported",
            state.clone(),
        ))
    }

    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `openid_federation`.
    async fn openid_federation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'openid_federation' client verification is not supported",
            state.clone(),
        ))
    }

    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `pre-registered`.
    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'preregistered' client verification is not supported",
            state.clone(),
        ))
    }

    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `redirect_uri`.
    ///
    /// See default implementation [redirect_uri].
    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        redirect_uri: &Url,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'redirect_uri' client verification is not supported",
            state.clone(),
        ))
    }

    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `verifier_attestation`.
    async fn verifier_attestation(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'verifier_attestation' client verification is not supported",
            state.clone(),
        ))
    }

    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `origin`.
    async fn origin(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'origin' client verification is not supported",
            state.clone(),
        ))
    }

    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `x509_san_dns`.
    ///
    /// See default implementation [x509_san_dns].
    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'x509_san_dns' client verification is not supported",
            state.clone(),
        ))
    }

    /// Performs verification on Authorization Request Objects when `client_id_prefix` is `x509_hash`.
    ///
    /// See default implementation [x509_hash].
    async fn x509_hash(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<(), Error> {
        let state = decoded_request.state();
        Err(Error::protocol_access_denied(
            "'x509_hash' client verification is not supported",
            state.clone(),
        ))
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
            if let Some(uri) = request.return_uri() {
                wallet.redirect_uri(&request, &uri).await?;
            } else if request.response_mode != ResponseMode::DcApi
                && request.response_mode != ResponseMode::DcApiJwt
            {
                return Err(Error::protocol_invalid_req(
                    &format!(
                        "'response_uri/redirect_uri' is required when response_mode is '{}'",
                        request.response_mode
                    ),
                    request.state(),
                ));
            }
            request
        }
        FetchedAuthorizationRequest::UnverifiedJwt(jwt) => {
            let request: AuthorizationRequestObject =
                decode_ensure_no_signature_jwt::<UntypedObject>(&jwt)
                    .map_err(|e| {
                        Error::protocol_invalid_req(
                            "unable to decode Authorization Request Object JWT",
                            None,
                        )
                        .add_source(e.into())
                    })?
                    .try_into()?;

            match request.client_id().get_prefix() {
                ClientIdPrefix::DecentralizedIdentifier => {
                    wallet.decentralized_identifier(&request, jwt).await?
                }
                ClientIdPrefix::OpenidFederation => wallet.openid_federation(&request, jwt).await?,
                ClientIdPrefix::PreRegistered => wallet.preregistered(&request, jwt).await?,
                ClientIdPrefix::VerifierAttestation => {
                    wallet.verifier_attestation(&request, jwt).await?
                }
                ClientIdPrefix::Origin => wallet.origin(&request, jwt).await?,
                ClientIdPrefix::X509SanDns => wallet.x509_san_dns(&request, jwt).await?,
                ClientIdPrefix::X509Hash => wallet.x509_hash(&request, jwt).await?,
                //  request cannot be signed for ClientIdPrefix::RedirectUri. link: https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-defined-client-identifier-s
                ClientIdPrefix::RedirectUri => {
                    return Err(Error::protocol(
                        ErrorType::WrongClientIdPrefix,
                        "Redirect uri prefix is not supported with signed request type",
                        None,
                    ));
                }
            }

            request
        }
    };

    validate_request_against_metadata(wallet, &request).await?;

    Ok(request)
}

fn decode_ensure_no_signature_jwt<Claims: DeserializeOwned>(
    jwt: &str,
) -> Result<Claims, ssi::claims::jws::Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jwt)?;

    if signature_b64.len() == 0 {
        let jws = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?.into_jws();
        serde_json::from_slice(&jws.payload).map_err(|err| ssi::claims::jws::Error::Json(err))
    } else {
        Err(ssi::claims::jws::Error::UnexpectedSignatureLength(
            0,
            signature_b64.len(),
        ))
    }
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

    let client_id_prefix = request.client_id().get_prefix();
    if !wallet_metadata
        .get_or_default::<ClientIdPrefixesSupported>()?
        .0
        .contains(&client_id_prefix)
    {
        return Err(Error::protocol_invalid_req(
            &format!(
                "wallet does not support client_id_prefix '{}'",
                client_id_prefix.to_string()
            ),
            state.clone(),
        ));
    }

    validate_response_type(request, wallet_metadata)?;

    let client_metadata = ClientMetadata::resolve(request).await?;
    validate_vp_formats_supported(&client_metadata, wallet_metadata, state.clone())?;

    Ok(())
}

fn validate_response_type(
    authorization_request_object: &AuthorizationRequestObject,
    wallet_metadata: &WalletMetadata,
) -> Result<(), Error> {
    let state = authorization_request_object.state();
    let response_type = authorization_request_object
        .get::<ResponseType>()
        .ok_or_else(|| Error::protocol_invalid_req("'response_type' is not declared, it is a required parameter of authorization request object", state.clone()))?
        .context("error occurred when retrieving response type")?;

    if !wallet_metadata
        .response_types_supported()
        .0
        .contains(&response_type)
    {
        return Err(Error::protocol_invalid_req(
            &format!(
                "response type = '{}' is not supported",
                String::from(response_type)
            ),
            state.clone(),
        ));
    }

    if ResponseType::VpTokenIdToken == response_type {
        let subject_syntax_types_supported = authorization_request_object
            .get::<ClientMetadata>()
            .ok_or_else(|| Error::protocol_invalid_req("'client_metadata' is required when response type is 'vp_token id_token'", state.clone()))?
            .context("error occurred when retrieving 'client_metadata'")?
            .0.get::<SubjectSyntaxTypesSupported>()
            .ok_or_else(|| Error::protocol_invalid_req("'subject_syntax_types_supported' is required when response type is 'vp_token id_token'", state.clone()))?
            .context("error occurred when retrieving 'subject_syntax_types_supported'")?;

        let unsupported = subject_syntax_types_supported.0.iter().find(|s| {
            !wallet_metadata
                .subject_syntax_types_supported()
                .contains(&s)
        });

        if let Some(unsupported) = unsupported {
            return Err(Error::protocol_invalid_req(
                &format!("subject syntax type = '{unsupported}' is not supported"),
                state.clone(),
            ));
        }
    }

    Ok(())
}

fn validate_vp_formats_supported(
    metadata: &ClientMetadata,
    wallet_metadata: &WalletMetadata,
    state: Option<String>,
) -> Result<(), Error> {
    let Ok(vp_formats) = metadata.0.get::<VpFormatsSupported>().parsing_error() else {
        return Ok(());
    };

    for (format, alg) in vp_formats.0 {
        let found = wallet_metadata
            .vp_formats_supported()
            .contains_claim_format_with_payload(&format, &alg);

        if !found {
            return Err(Error::protocol_vp_formats_not_supported(
                &format!(
                    "unsupported vp format = '{}' with alg values '{}'",
                    String::from(format.to_owned()),
                    serde_json::to_string(&alg).unwrap_or_else(|_| "".to_string())
                ),
                state,
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
}

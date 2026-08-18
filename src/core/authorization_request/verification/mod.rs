use super::{
    parameters::{ClientIdPrefix, ClientMetadata},
    AuthorizationRequestObject, FetchedAuthorizationRequest,
};
use crate::core::authorization_request::parameters::{ResponseMode, ResponseType};
use crate::core::error::Error;
use crate::core::metadata::parameters::{SubjectSyntaxTypesSupported, VpFormatsSupported};
use crate::core::metadata::WalletMetadata;
use crate::core::{
    metadata::parameters::wallet::ClientIdPrefixesSupported,
    object::{ParsingErrorContext, UntypedObject},
};
use crate::wallet::Wallet;
use anyhow::{Context, Result};
use async_trait::async_trait;
use ssi::claims::jws::split_jws;
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

    async fn redirect_uri_jwt(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: &str,
    ) -> Result<(), Error> {
        let signed = is_signed_jwt(request_jwt).map_err(|e| {
            Error::protocol_invalid_req("unable to decode Authorization Request Object JWT", None)
                .add_source(e.into())
        })?;
        if signed {
            return Err(Error::protocol_invalid_req(
                "Client id prefix 'redirect_uri' can not be used in signed auth requests",
                decoded_request.state().clone(),
            ));
        }
        if let Some(return_url) = &decoded_request.return_uri {
            self.redirect_uri(decoded_request, return_url).await
        } else {
            Err(Error::internal(anyhow::Error::msg(
                "redirect_uri_jwt was called for a request without return_uri",
            )))
        }
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
                ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
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
                ClientIdPrefix::RedirectUri => wallet.redirect_uri_jwt(&request, &jwt).await?,
            }

            request
        }
    };

    validate_request_against_metadata(wallet, &request).await?;

    Ok(request)
}

/// Checks that JWT token has non-empty signature part.
/// Does **not** validate signature.
fn is_signed_jwt(jwt: &str) -> Result<bool, ssi::claims::jws::Error> {
    let (_, _, signature) = split_jws(jwt)?;

    Ok(signature.len() > 0)
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

/// Rejects the request when the Wallet does not support any of the formats the Verifier advertises.
fn validate_vp_formats_supported(
    metadata: &ClientMetadata,
    wallet_metadata: &WalletMetadata,
    state: Option<String>,
) -> Result<(), Error> {
    let Ok(vp_formats) = metadata.0.get::<VpFormatsSupported>().parsing_error() else {
        return Ok(());
    };

    if vp_formats.0.is_empty() {
        return Err(Error::protocol_vp_formats_not_supported(
            "the verifier advertised an empty 'vp_formats_supported' object",
            state,
        ));
    }

    let supported = wallet_metadata.vp_formats_supported();
    let overlaps = vp_formats
        .0
        .iter()
        .any(|(format, alg)| supported.contains_claim_format_with_payload(format, alg));

    if overlaps {
        return Ok(());
    }

    let offered = vp_formats
        .0
        .iter()
        .map(|(format, alg)| {
            format!(
                "'{}' with alg values '{}'",
                String::from(format.to_owned()),
                serde_json::to_string(alg).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    Err(Error::protocol_vp_formats_not_supported(
        &format!("none of the vp formats offered by the verifier are supported: {offered}"),
        state,
    ))
}

#[cfg(test)]
mod test {
    use super::validate_vp_formats_supported;
    use crate::core::authorization_request::parameters::ClientMetadata;
    use crate::core::error::{Error, ErrorType};
    use crate::core::metadata::WalletMetadata;
    use crate::core::object::UntypedObject;
    use serde_json::json;

    const SD_JWT_ONLY_WALLET: &str = r#"{
        "issuer": "https://self-issued.me/v2",
        "authorization_endpoint": "openid4vp://",
        "response_types_supported": ["vp_token"],
        "vp_formats_supported": {
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["EdDSA", "ES256"],
                "kb-jwt_alg_values": ["EdDSA", "ES256"]
            }
        }
    }"#;

    fn wallet_metadata() -> WalletMetadata {
        WalletMetadata::try_from(serde_json::from_str::<UntypedObject>(SD_JWT_ONLY_WALLET).unwrap())
            .unwrap()
    }

    fn client_metadata(value: serde_json::Value) -> ClientMetadata {
        ClientMetadata::try_from(value).unwrap()
    }

    fn sd_jwt() -> serde_json::Value {
        json!({
            "sd-jwt_alg_values": ["EdDSA", "ES256"],
            "kb-jwt_alg_values": ["EdDSA", "ES256"]
        })
    }

    fn mso_mdoc() -> serde_json::Value {
        json!({
            "issuerauth_alg_values": [-7, -8],
            "deviceauth_alg_values": [-7, -8]
        })
    }

    fn error_type(error: Error) -> ErrorType {
        match error {
            Error::Protocol(err) => err.r#type,
            Error::Internal(err) => panic!("expected a protocol error, got: {err}"),
        }
    }

    #[test]
    fn a_format_the_wallet_lacks_is_accepted_while_another_one_overlaps() {
        // OpenID4VP 1.0, Section 8.5: the request is refused only when the Wallet supports *none*
        // of the offered formats. Here the request can still be satisfied over `dc+sd-jwt`.
        let metadata = client_metadata(json!({
            "vp_formats_supported": {
                "dc+sd-jwt": sd_jwt(),
                "mso_mdoc": mso_mdoc()
            }
        }));

        assert!(validate_vp_formats_supported(&metadata, &wallet_metadata(), None).is_ok());
    }

    #[test]
    fn a_verifier_the_wallet_shares_no_format_with_is_rejected() {
        let metadata = client_metadata(json!({
            "vp_formats_supported": { "mso_mdoc": mso_mdoc() }
        }));

        let err = validate_vp_formats_supported(&metadata, &wallet_metadata(), None).unwrap_err();

        assert_eq!(error_type(err), ErrorType::VpFormatsNotSupported);
    }

    #[test]
    fn an_overlapping_format_carrying_no_common_algorithm_is_rejected() {
        let metadata = client_metadata(json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["RS256"],
                    "kb-jwt_alg_values": ["RS256"]
                }
            }
        }));

        let err = validate_vp_formats_supported(&metadata, &wallet_metadata(), None).unwrap_err();

        assert_eq!(error_type(err), ErrorType::VpFormatsNotSupported);
    }

    #[test]
    fn the_state_is_carried_into_the_error() {
        let metadata = client_metadata(json!({
            "vp_formats_supported": { "mso_mdoc": mso_mdoc() }
        }));
        let state = Some("state-1".to_string());

        let err = validate_vp_formats_supported(&metadata, &wallet_metadata(), state.clone())
            .unwrap_err();

        match err {
            Error::Protocol(err) => assert_eq!(err.state, state),
            Error::Internal(err) => panic!("expected a protocol error, got: {err}"),
        }
    }

    #[test]
    fn metadata_without_vp_formats_is_accepted() {
        let metadata = client_metadata(json!({ "client_name": "Verifier" }));

        assert!(validate_vp_formats_supported(&metadata, &wallet_metadata(), None).is_ok());
    }

    #[test]
    fn an_empty_vp_formats_object_is_rejected() {
        let metadata = client_metadata(json!({ "vp_formats_supported": {} }));
        let err = validate_vp_formats_supported(&metadata, &wallet_metadata(), None).unwrap_err();

        assert_eq!(error_type(err), ErrorType::VpFormatsNotSupported);
    }
}

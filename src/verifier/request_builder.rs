use anyhow::{anyhow, Context, Result};
use std::collections::HashSet;
use url::Url;

use super::Verifier;
use crate::core::authorization_request::parameters::{ClientMetadata, RedirectUri, ResponseUri};
use crate::core::authorization_request::SignedAuthorizationRequest;
use crate::core::dcql::DCQL;
use crate::core::error::Error;
use crate::core::metadata::parameters::SubjectSyntaxTypesSupported;
use crate::core::{
    authorization_request::{
        parameters::{ResponseMode, ResponseType},
        AuthorizationRequestObject, RequestIndirection,
    },
    metadata::{parameters::wallet::AuthorizationEndpoint, WalletMetadata},
    object::{ParsingErrorContext, TypedParameter, UntypedObject},
    presentation_definition::PresentationDefinition,
};
use crate::utils::{WasmNotSend, WasmNotSync};
use crate::verifier::by_reference::ByReference;
use crate::verifier::client::Client;

#[derive(Debug, Clone)]
#[must_use]
pub struct RequestBuilder<'a, C: Client + WasmNotSend + WasmNotSync> {
    presentation_definition: Option<PresentationDefinition>,
    dcql: Option<DCQL>,
    request_parameters: UntypedObject,
    verifier: &'a Verifier<C>,
}

#[derive(Debug, Clone)]
pub enum RequestType {
    Plain,
    SignedJwt(ByReference),
}

impl<'a, C: Client + WasmNotSend + WasmNotSync> RequestBuilder<'a, C> {
    pub(crate) fn new(verifier: &'a Verifier<C>) -> Self {
        Self {
            presentation_definition: None,
            request_parameters: verifier.default_request_params.clone(),
            dcql: None,
            verifier,
        }
    }

    /// Set the presentation definition.
    pub fn with_presentation_definition(
        mut self,
        presentation_definition: PresentationDefinition,
    ) -> Self {
        self.presentation_definition = Some(presentation_definition);
        self
    }

    /// Set the dcql query.
    pub fn with_dcql(mut self, dcql: DCQL) -> Self {
        self.dcql = Some(dcql);
        self
    }

    /// Set or override the default authorization request parameters.
    pub fn with_request_parameter<T: TypedParameter>(mut self, t: T) -> Self {
        self.request_parameters.insert(t);
        self
    }

    /// Build the request.
    ///
    /// ## Returns
    /// - URL that the application frontend should use to drive the user to their wallet application.
    /// - Authorization Request JWT that must be bind to `request_uri` endpoint if `pass_by_reference` is true.
    pub async fn build(
        mut self,
        wallet_metadata: &WalletMetadata,
        request_type: RequestType,
    ) -> Result<(Url, Option<String>), Error> {
        let client_id = self.verifier.client.id();
        let client_id_prefix = self.verifier.client.prefix();
        let _ = self.request_parameters.insert(client_id.clone());

        match (
            self.dcql.to_owned(),
            self.presentation_definition.to_owned(),
        ) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(Error::internal(anyhow!(
                    "either presentation definition or dcql query must be present"
                )));
            }
            (Some(dcql), None) => {
                Self::validate_dcql(&dcql)?;
                self.request_parameters.insert(dcql);
            }
            (None, Some(presentation_definition)) => {
                Self::validate_presentation_definition(&presentation_definition)?;
                self.request_parameters.insert(presentation_definition);
            }
        }
        self.validate_response_type(&wallet_metadata)?;

        if !wallet_metadata.is_client_id_prefix_supported(&client_id_prefix) {
            let prefix = String::from(client_id_prefix);
            return Err(Error::internal(anyhow!(
                "the wallet does not support the client_id_prefix '{prefix}'"
            )));
        }

        match self
            .request_parameters
            .get::<ResponseMode>()
            .context("error occurred when retrieving response mode")?
        {
            Ok(ResponseMode::Unsupported(r)) => {
                return Err(Error::internal(anyhow!("unsupported response_mode: {r}")))
            }
            Ok(ResponseMode::DirectPost) | Ok(ResponseMode::DirectPostJwt) => {
                self.request_parameters
                    .insert(ResponseUri(self.verifier.submission_endpoint.clone()));
            }
            Ok(ResponseMode::DCAPI) | Ok(ResponseMode::DCAPIJwt) | Err(_) => {
                self.request_parameters
                    .insert(RedirectUri(self.verifier.submission_endpoint.clone()));
            }
        }
        let authorization_request_object: AuthorizationRequestObject =
            self.request_parameters.try_into().context(
                "unable to construct the Authorization Request from provided request parameters",
            )?;

        let authorization_endpoint = wallet_metadata
            .get::<AuthorizationEndpoint>()
            .parsing_error()?
            .0;

        match request_type {
            RequestType::Plain => {
                let authorization_request_url = authorization_request_object
                    .to_url(authorization_endpoint)
                    .context("unable to generate authorization request URL")?;

                Ok((authorization_request_url, None))
            }
            RequestType::SignedJwt(pass_by_reference) => {
                let auth_req_jwt = self
                    .verifier
                    .client
                    .generate_request_object_jwt(&authorization_request_object)
                    .await?;

                let request_indirection = match pass_by_reference {
                    ByReference::False => RequestIndirection::ByValue(auth_req_jwt.clone()),
                    ByReference::True(rr) => RequestIndirection::ByReference(rr),
                };
                let signed_auth_req = SignedAuthorizationRequest {
                    client_id: client_id.get_full_id().to_owned(),
                    request_indirection,
                };

                let authorization_request_url = signed_auth_req
                    .to_url(authorization_endpoint)
                    .context("unable to generate authorization request URL")?;

                Ok((authorization_request_url, Some(auth_req_jwt)))
            }
        }
    }

    fn validate_dcql(dcql: &DCQL) -> Result<(), Error> {
        let cred_ids = dcql
            .credentials()
            .iter()
            .map(|v| v.id().as_str())
            .collect::<HashSet<_>>();
        if cred_ids.len() != dcql.credentials().len() {
            return Err(Error::internal(anyhow!(
                "Credential IDs must be unique in the dcql query"
            )));
        }
        for cred in dcql.credentials() {
            match (cred.claims(), cred.claim_sets()) {
                (Some(claims), Some(_)) => {
                    for claim in claims {
                        if claim.id().is_none() {
                            return Err(Error::internal(anyhow!(
                                "Claim id cannot be empty if Claim set is given"
                            )));
                        }
                    }
                    let claim_ids = claims
                        .iter()
                        .map(|v| v.id().map(|id| id.as_str()))
                        .filter(|v| v.is_some())
                        .collect::<HashSet<_>>();
                    if claim_ids.len() != claims.len() {
                        return Err(Error::internal(anyhow!(
                            "Claim IDs must be unique in the Credential query"
                        )));
                    }
                }
                (None, Some(_)) => {
                    return Err(Error::internal(anyhow!(
                        "Claim set cannot be given if Claims is empty"
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_presentation_definition(
        presentation_definition: &PresentationDefinition,
    ) -> Result<(), Error> {
        if presentation_definition.id().is_empty() {
            return Err(Error::internal(anyhow!(
                "presentation definition 'id' cannot be empty"
            )));
        }

        if presentation_definition.input_descriptors().is_empty() {
            return Err(Error::internal(anyhow!(
                "'input_descriptors' of presentation definition cannot be empty"
            )));
        }

        Ok(())
    }

    fn validate_response_type(&self, wallet_metadata: &WalletMetadata) -> Result<(), Error> {
        let response_type = self
            .request_parameters
            .get::<ResponseType>()
            .context("response type is required, see `with_request_parameter`")?
            .context("error occurred when retrieving response type")?;

        if !wallet_metadata
            .response_types_supported()
            .0
            .contains(&response_type)
        {
            return Err(Error::internal(anyhow!(
                "response type = '{}' is not supported by the wallet",
                String::from(response_type)
            )));
        }

        if ResponseType::VpTokenIdToken == response_type {
            let subject_syntax_types_supported = self
                .request_parameters
                .get::<ClientMetadata>()
                .context("'client_metadata' is required while building an authorization request with 'vp_token id_token' response type")?
                .context("error occurred when retrieving 'client_metadata'")?
                .0.get::<SubjectSyntaxTypesSupported>()
                .context("'subject_syntax_types_supported' is required while building an authorization request with 'vp_token id_token' response type")?
                .context("error occurred when retrieving 'subject_syntax_types_supported'")?;

            let unsupported = subject_syntax_types_supported.0.iter().find(|s| {
                !wallet_metadata
                    .subject_syntax_types_supported()
                    .0
                    .contains(&s)
            });

            if let Some(unsupported) = unsupported {
                return Err(Error::internal(anyhow!(
                    "subject syntax type = '{unsupported}' is not supported by the wallet"
                )));
            }
        }

        Ok(())
    }
}

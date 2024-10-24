use anyhow::{anyhow, Context, Result};
use url::Url;

use super::Verifier;
use crate::core::authorization_request::parameters::ResponseUri;
use crate::core::error::Error;
use crate::core::{
    authorization_request::{
        self,
        parameters::{ResponseMode, ResponseType},
        AuthorizationRequest, AuthorizationRequestObject, RequestIndirection,
    },
    metadata::{
        parameters::wallet::{AuthorizationEndpoint, ClientIdSchemesSupported},
        WalletMetadata,
    },
    object::{ParsingErrorContext, TypedParameter, UntypedObject},
    presentation_definition::PresentationDefinition,
};
use crate::verifier::by_reference::ByReference;
use crate::verifier::client::Client;

#[derive(Debug, Clone)]
#[must_use]
pub struct RequestBuilder<'a, C: Client + Send + Sync> {
    presentation_definition: Option<PresentationDefinition>,
    request_parameters: UntypedObject,
    verifier: &'a Verifier<C>,
}

impl<'a, C: Client + Send + Sync> RequestBuilder<'a, C> {
    pub(crate) fn new(verifier: &'a Verifier<C>) -> Self {
        Self {
            presentation_definition: None,
            request_parameters: verifier.default_request_params.clone(),
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
        pass_by_reference: ByReference,
    ) -> Result<(Url, String), Error> {
        let client_id = self.verifier.client.id();
        let client_id_scheme = self.verifier.client.scheme();

        let _ = self.request_parameters.insert(client_id.clone());
        let _ = self.request_parameters.insert(client_id_scheme.clone());

        let Some(presentation_definition) = self.presentation_definition else {
            return Err(Error::internal(anyhow!(
                "presentation definition is required, see `with_presentation_definition`"
            )));
        };

        let _ = self.request_parameters.insert(
            authorization_request::parameters::PresentationDefinition::try_from(
                presentation_definition.clone(),
            )
            .context("failed to construct PresentationDefinition request parameter")?,
        );

        let _ = self
            .request_parameters
            .get::<ResponseType>()
            .context("response type is required, see `with_request_parameter`")?
            .context("error occurred when retrieving response type")?;

        match self
            .request_parameters
            .get::<ResponseMode>()
            .context("response mode is required, see `with_request_parameter`")?
            .context("error occurred when retrieving response mode")?
        {
            ResponseMode::Unsupported(r) => {
                return Err(Error::internal(anyhow!("unsupported response_mode: {r}")))
            }
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
                self.request_parameters
                    .insert(ResponseUri(self.verifier.submission_endpoint.clone()));
            }
        }

        if !wallet_metadata
            .get_or_default::<ClientIdSchemesSupported>()?
            .0
            .contains(client_id_scheme)
        {
            return Err(Error::internal(anyhow!(
                "the wallet does not support the client_id_scheme '{client_id_scheme}'"
            )));
        }

        let authorization_request_object: AuthorizationRequestObject =
            self.request_parameters.try_into().context(
                "unable to construct the Authorization Request from provided request parameters",
            )?;

        let authorization_request_jwt = self
            .verifier
            .client
            .generate_request_object_jwt(&authorization_request_object)
            .await?;

        let request_indirection = match pass_by_reference {
            ByReference::False => RequestIndirection::ByValue(authorization_request_jwt.clone()),
            ByReference::True { at } => RequestIndirection::ByReference(at),
        };

        let authorization_endpoint = wallet_metadata
            .get::<AuthorizationEndpoint>()
            .parsing_error()?
            .0;

        let authorization_request_url = AuthorizationRequest {
            client_id: client_id.0.clone(),
            request_indirection,
        }
        .to_url(authorization_endpoint)
        .context("unable to generate authorization request URL")?;

        Ok((authorization_request_url, authorization_request_jwt))
    }
}

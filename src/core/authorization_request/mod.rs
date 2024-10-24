use std::future::Future;
use std::ops::{Deref, DerefMut};

use anyhow::anyhow;
use oauth2::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use url::Url;

use crate::wallet::Wallet;

use self::{
    parameters::{
        ClientId, ClientIdScheme, Nonce, PresentationDefinition, PresentationDefinitionUri,
        RedirectUri, ResponseMode, ResponseType, ResponseUri,
    },
    verification::verify_request,
};
use super::object::{ParsingErrorContext, UntypedObject};
use crate::core::authorization_request::parameters::ClientMetadata;
use crate::core::error::Error;
use crate::core::error::ErrorType::{
    InvalidPresentationDefinitionReference, InvalidPresentationDefinitionUri,
};
use crate::core::util::http::{create_get_request, MIME_TYPE_JSON, MIME_TYPE_TEXT_PLAIN};

pub mod parameters;
pub mod verification;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct AuthorizationRequestObject(
    UntypedObject,
    ClientId,
    ClientIdScheme,
    ResponseMode,
    ResponseType,
    PresentationDefinitionIndirection,
    Url,
    Nonce,
    ClientMetadata,
);

/// An Authorization Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    #[serde(flatten)]
    pub request_indirection: RequestIndirection,
}

/// A RequestObject, passed by value or by reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestIndirection {
    #[serde(rename = "request")]
    ByValue(String),
    #[serde(rename = "request_uri")]
    ByReference(Url),
}

/// A PresentationDefinition, passed by value or by reference
#[derive(Debug, Clone)]
pub enum PresentationDefinitionIndirection {
    ByValue(PresentationDefinition),
    ByReference(Url),
}

impl AuthorizationRequest {
    /// Validate the [AuthorizationRequest] according to the client_id scheme and return the parsed
    /// [RequestObject].
    ///
    /// Custom wallet metadata can be provided, otherwise the default metadata for this profile is used.
    pub async fn validate<W, HC, F, RE>(
        self,
        wallet: &W,
        http_client_fn: HC,
    ) -> Result<AuthorizationRequestObject, Error>
    where
        W: Wallet + ?Sized,
        HC: Fn(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send + Sync,
    {
        let jwt = match self.request_indirection {
            RequestIndirection::ByValue(jwt) => jwt,
            RequestIndirection::ByReference(url) => {
                let resp = http_client_fn(create_get_request(&url, MIME_TYPE_TEXT_PLAIN))
                    .await
                    .map_err(|e| Error::Internal(anyhow!(e)))?;

                if !resp.status_code.is_success() {
                    return Err(Error::protocol_invalid_req(
                        "failed to get authorization request object",
                    ));
                }

                String::from_utf8(resp.body).map_err(|e| {
                    Error::protocol_invalid_req("cannot parse authorization request object")
                        .add_source(e.into())
                })?
            }
        };
        let aro = verify_request(wallet, jwt, http_client_fn).await?;
        if self.client_id.as_str() != aro.client_id().0.as_str() {
            return Err(Error::protocol_invalid_req(&format!(
                "Authorization Request and Request Object have different client ids: '{}' vs. '{}'",
                self.client_id,
                aro.client_id().0
            )));
        }

        Ok(aro)
    }

    /// Try to resolve `authorization request jwt` and return the `response_uri`.
    pub async fn resolve_response_uri<HC, F, RE>(self, http_client_fn: HC) -> Result<Url, Error>
    where
        HC: Fn(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send + Sync,
    {
        let jwt = match self.request_indirection {
            RequestIndirection::ByValue(jwt) => jwt,
            RequestIndirection::ByReference(url) => {
                let resp = http_client_fn(create_get_request(&url, MIME_TYPE_TEXT_PLAIN))
                    .await
                    .map_err(|e| Error::Internal(anyhow!(e)))?;

                if !resp.status_code.is_success() {
                    return Err(Error::internal(anyhow!(
                        "failed to get authorization request object"
                    )));
                }

                String::from_utf8(resp.body).map_err(|e| {
                    Error::internal(anyhow!("cannot parse authorization request object: {e}"))
                })?
            }
        };

        let aro: AuthorizationRequestObject = ssi::jwt::decode_unverified::<UntypedObject>(&jwt)
            .map_err(|e| {
                Error::internal(anyhow!(
                    "unable to decode Authorization Request Object JWT: {e}"
                ))
            })?
            .try_into()?;

        Ok(aro.return_uri().to_owned())
    }

    /// Encode as [Url], using the `authorization_endpoint` as a base.
    /// ```
    /// # use oid4vp::core::authorization_request::AuthorizationRequest;
    /// # use oid4vp::core::authorization_request::RequestIndirection;
    /// # use url::Url;
    /// let authorization_endpoint: Url = "example://".parse().unwrap();
    /// let authorization_request = AuthorizationRequest {
    ///     client_id: "xyz".to_string(),
    ///     request_indirection: RequestIndirection::ByValue("test".to_string()),
    /// };
    ///
    /// let authorization_request_url = authorization_request.to_url(authorization_endpoint).unwrap();
    ///
    /// assert_eq!(authorization_request_url.as_str(), "example://?client_id=xyz&request=test");
    /// ```
    pub fn to_url(self, mut authorization_endpoint: Url) -> Result<Url, Error> {
        let query = serde_urlencoded::to_string(self).map_err(|e| Error::Internal(e.into()))?;
        authorization_endpoint.set_query(Some(&query));
        Ok(authorization_endpoint)
    }

    /// Parse from [Url], validating the authorization_endpoint.
    /// ```
    /// # use oid4vp::core::authorization_request::AuthorizationRequest;
    /// # use oid4vp::core::authorization_request::RequestIndirection;
    /// # use url::Url;
    /// let url: Url = "example://?client_id=xyz&request=test".parse().unwrap();
    /// let authorization_endpoint: Url = "example://".parse().unwrap();
    ///
    /// let authorization_request = AuthorizationRequest::from_url(
    ///     &url,
    ///     &authorization_endpoint
    /// ).unwrap();
    ///
    /// assert_eq!(authorization_request.client_id, "xyz");
    ///
    /// let RequestIndirection::ByValue(request_object) =
    ///     authorization_request.request_indirection
    /// else {
    ///     panic!("expected request-by-value")
    /// };
    ///
    /// assert_eq!(request_object, "test");
    /// ```
    pub fn from_url(url: &Url, authorization_endpoint: &Url) -> Result<Self, Error> {
        let query = url
            .query()
            .ok_or(Error::protocol_invalid_req(
                "missing query params in Authorization Request uri",
            ))?
            .to_string();
        let fnd = url.authority();
        let exp = authorization_endpoint.authority();
        if fnd != exp {
            return Err(Error::protocol_invalid_req(&format!(
                "unexpected authorization_endpoint authority, expected '{exp}', received '{fnd}'"
            )));
        }
        let fnd = url.path();
        let exp = authorization_endpoint.path();
        if fnd != exp {
            return Err(Error::protocol_invalid_req(&format!(
                "unexpected authorization_endpoint path, expected '{exp}', received '{fnd}'"
            )));
        }
        Self::from_query_params(&query)
    }

    /// Parse from urlencoded query parameters.
    /// ```
    /// # use oid4vp::core::authorization_request::AuthorizationRequest;
    /// # use oid4vp::core::authorization_request::RequestIndirection;
    /// let query = "client_id=xyz&request=test";
    ///
    /// let authorization_request = AuthorizationRequest::from_query_params(query).unwrap();
    ///
    /// assert_eq!(authorization_request.client_id, "xyz");
    ///
    /// let RequestIndirection::ByValue(request_object) = authorization_request.request_indirection
    /// else { panic!("expected request-by-value") };
    /// assert_eq!(request_object, "test");
    /// ```
    pub fn from_query_params(query_params: &str) -> Result<Self, Error> {
        serde_urlencoded::from_str(query_params).map_err(|e| {
            Error::protocol_invalid_req("unable to parse Authorization Request from query params")
                .add_source(e.into())
        })
    }
}

impl AuthorizationRequestObject {
    pub fn client_id(&self) -> &ClientId {
        &self.1
    }

    pub fn client_id_scheme(&self) -> &ClientIdScheme {
        &self.2
    }

    pub async fn resolve_presentation_definition<HC, F, RE>(
        &self,
        http_client_fn: HC,
    ) -> Result<PresentationDefinition, Error>
    where
        HC: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static + Sync + Send,
    {
        match &self.5 {
            PresentationDefinitionIndirection::ByValue(by_value) => Ok(by_value.clone()),
            PresentationDefinitionIndirection::ByReference(by_reference) => {
                let resp = http_client_fn(create_get_request(&by_reference, MIME_TYPE_JSON))
                    .await
                    .map_err(|e| Error::Internal(anyhow!(e)))?;

                if !resp.status_code.is_success() {
                    return Err(Error::protocol(
                        InvalidPresentationDefinitionUri,
                        &format!(
                            "failed to get Presentation Definition: status_code={}",
                            resp.status_code,
                        ),
                    ));
                }

                let presentation_def = serde_json::from_slice::<Json>(&resp.body)
                    .map_err(|e| Error::internal(e.into()))?;
                PresentationDefinition::try_from(presentation_def).map_err(|e| {
                    Error::protocol(
                        InvalidPresentationDefinitionReference,
                        "failed to get parse Presentation Definition: {e}",
                    )
                    .add_source(e.into())
                })
            }
        }
    }

    pub fn is_id_token_requested(&self) -> Option<bool> {
        match self.4 {
            ResponseType::VpToken => Some(false),
            ResponseType::VpTokenIdToken => Some(true),
            ResponseType::Unsupported(_) => None,
        }
    }

    pub fn response_mode(&self) -> &ResponseMode {
        &self.3
    }

    pub fn response_type(&self) -> &ResponseType {
        &self.4
    }

    /// Uri to submit the response at.
    ///
    /// AKA [ResponseUri] or [RedirectUri] depending on [ResponseMode].
    pub fn return_uri(&self) -> &Url {
        &self.6
    }

    pub fn nonce(&self) -> &Nonce {
        &self.7
    }

    pub fn client_metadata(&self) -> &ClientMetadata {
        &self.8
    }
}

impl From<AuthorizationRequestObject> for UntypedObject {
    fn from(value: AuthorizationRequestObject) -> Self {
        let mut inner = value.0;
        inner.insert(value.1);
        inner.insert(value.2);
        inner
    }
}

impl TryFrom<UntypedObject> for AuthorizationRequestObject {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        let client_id = value.get().parsing_error()?;
        let client_id_scheme = value.get().parsing_error().map_err(|e| {
            Error::protocol_invalid_req("omitting a client_id_scheme is not supported")
                .add_source(e.into())
        })?;

        let redirect_uri = value.get::<RedirectUri>();
        let response_uri = value.get::<ResponseUri>();

        let (return_uri, response_mode) = match (
            redirect_uri,
            response_uri,
            value.get_or_default::<ResponseMode>().parsing_error()?,
        ) {
            (_, _, ResponseMode::Unsupported(m)) => {
                return Err(Error::protocol_invalid_req(&format!(
                    "this 'response_mode' ({m}) is not supported"
                )))
            }
            (Some(_), Some(_), _) => {
                return Err(Error::protocol_invalid_req(
                    "'response_uri' and 'redirect_uri' are mutually exclusive",
                ))
            }
            (_, None, response_mode @ ResponseMode::DirectPost)
            | (_, None, response_mode @ ResponseMode::DirectPostJwt) => {
                return Err(Error::protocol_invalid_req(&format!(
                    "'response_uri' is required for this 'response_mode' ({response_mode})"
                )))
            }
            (_, Some(uri), response_mode @ ResponseMode::DirectPost)
            | (_, Some(uri), response_mode @ ResponseMode::DirectPostJwt) => (
                uri.parsing_error()
                    .map_err(|e| {
                        Error::protocol_invalid_req("could not parse a 'response_uri'")
                            .add_source(e.into())
                    })?
                    .0,
                response_mode,
            ),
        };

        let response_type: ResponseType = value.get().parsing_error()?;

        let pd_indirection = match (
            value.get::<PresentationDefinition>(),
            value.get::<PresentationDefinitionUri>(),
        ) {
            (None, None) => return Err(Error::protocol_invalid_req(
                "one of 'presentation_definition' and 'presentation_definition_uri' are required",
            )),
            (Some(_), Some(_)) => {
                return Err(Error::protocol_invalid_req(
                    "'presentation_definition' and 'presentation_definition_uri' are mutually exclusive",
                ))
            }
            (Some(by_value), None) => {
                PresentationDefinitionIndirection::ByValue(by_value.parsing_error().map_err(|e| Error::protocol_invalid_req(
                    "could parse a 'presentation_definition'",
                ).add_source(e.into()))?)
            }
            (None, Some(by_reference)) => {
                PresentationDefinitionIndirection::ByReference(by_reference.parsing_error().map_err(|e| Error::protocol(
                    InvalidPresentationDefinitionUri,
                    "could parse a 'presentation_definition_uri'",
                ).add_source(e.into()))?.0)
            }
        };

        let nonce = value.get().parsing_error()?;
        let client_metadata = value.get().parsing_error()?;

        Ok(Self(
            value,
            client_id,
            client_id_scheme,
            response_mode,
            response_type,
            pd_indirection,
            return_uri,
            nonce,
            client_metadata,
        ))
    }
}

impl Deref for AuthorizationRequestObject {
    type Target = UntypedObject;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AuthorizationRequestObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

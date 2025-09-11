use std::ops::{Deref, DerefMut};

use anyhow::anyhow;
use http::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use url::form_urlencoded::byte_serialize;
use url::Url;

use crate::wallet::Wallet;

use self::parameters::{
    ClientId, Nonce, PresentationDefinitionUri, RedirectUri, ResponseMode, ResponseType,
    ResponseUri,
};
use super::object::{ParsingErrorContext, UntypedObject};
use crate::core::authorization_request::parameters::{
    ClientMetadata, HttpMethodForAuth, State, TransactionData, TransactionDataItem, WalletNonce,
};
use crate::core::authorization_request::verification::verify_request;
use crate::core::dcql::DCQL;
use crate::core::error::ErrorType::{
    InvalidDCQLFormat, InvalidPresentationDefinitionFormat, InvalidPresentationDefinitionReference,
    InvalidPresentationDefinitionUri,
};
use crate::core::error::{Error, ErrorType};
use crate::core::presentation_definition::PresentationDefinition;
use crate::core::util::http::{
    create_get_request, create_post_request, AsyncHttpClient, MIME_TYPE_FORM_URLENCODED,
    MIME_TYPE_JSON, MIME_TYPE_OAUTH_REQ_JWT,
};
use crate::utils::{WasmNotSend, WasmNotSync};

pub mod parameters;
pub mod verification;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct AuthorizationRequestObject {
    inner: UntypedObject,
    client_id: ClientId,
    response_mode: ResponseMode,
    response_type: ResponseType,
    presentation_query: PresentationQuery,
    return_uri: Url,
    nonce: Nonce,
    client_metadata: ClientMetadata,
}

/// An Authorization Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorizationRequest {
    #[serde(untagged)]
    Plain(AuthorizationRequestObject),
    #[serde(untagged)]
    Signed(SignedAuthorizationRequest),
}

/// An Authorization Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuthorizationRequest {
    pub client_id: String,
    #[serde(flatten)]
    pub request_indirection: RequestIndirection,
}

/// Fetched Authorization Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FetchedAuthorizationRequest {
    UnverifiedJwt(String),
    #[serde(untagged)]
    Plain(AuthorizationRequestObject),
}

/// A RequestObject, passed by value or by reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestIndirection {
    #[serde(rename = "request")]
    ByValue(String),
    #[serde(untagged)]
    ByReference(RequestReference),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestReference {
    pub request_uri: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_method: Option<HttpMethodForAuth>,
}
/// A DCQL passed as value or PresentationDefinition passed by value or by reference
#[derive(Debug, Clone)]
pub enum PresentationQuery {
    DCQL(DCQL),
    PresentationDefinition(PresentationDefinitionIndirection),
}

#[derive(Debug, Clone)]
pub enum PresentationDefinitionIndirection {
    ByValue(PresentationDefinition),
    ByReference(Url),
}

/// A common enum type to define either 'dcql_query' and 'presentation_definition'
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ResolvedPresentationQuery {
    #[serde(rename = "dcql_query")]
    DCQL(DCQL),
    #[serde(rename = "presentation_definition")]
    PresentationDefinition(PresentationDefinition),
}

impl ResolvedPresentationQuery {
    pub fn get_presentation_definition(&self) -> Option<PresentationDefinition> {
        if let ResolvedPresentationQuery::PresentationDefinition(p) = self {
            return Some(p.to_owned());
        }
        None
    }

    pub fn get_dcql(&self) -> Option<DCQL> {
        if let ResolvedPresentationQuery::DCQL(d) = self {
            return Some(d.to_owned());
        }
        None
    }
}

impl AuthorizationRequest {
    /// Validate the [AuthorizationRequest] according to the client id prefix and return the parsed
    /// [AuthorizationRequestObject].
    ///
    /// Custom wallet metadata can be provided, otherwise the default metadata for this profile is used.
    pub async fn validate<W>(self, wallet: &W) -> Result<AuthorizationRequestObject, Error>
    where
        W: Wallet + ?Sized,
    {
        let aro = match self {
            AuthorizationRequest::Plain(aro) => {
                let fetched_auth_req = FetchedAuthorizationRequest::Plain(aro);
                verify_request(wallet, fetched_auth_req).await?
            }
            AuthorizationRequest::Signed(signed) => signed.resolve_auth_request(wallet).await?,
        };

        Ok(aro)
    }

    /// Parse from [Url], validating the authorization_endpoint.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// # use url::Url;
    /// let url: Url = "example://?client_id=xyz&request=test".parse().unwrap();
    /// let authorization_endpoint: Url = "example://".parse().unwrap();
    ///
    /// let AuthorizationRequest::Signed(authorization_request) = AuthorizationRequest::from_url(
    ///     &url,
    ///     &authorization_endpoint
    /// ).unwrap()
    /// else {
    ///     panic!("expected signed authorization request")
    /// };
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
                None,
            ))?
            .to_string();
        let fnd = url.authority();
        let exp = authorization_endpoint.authority();
        if fnd != exp {
            return Err(Error::protocol_invalid_req(
                &format!(
                "unexpected authorization_endpoint authority, expected '{exp}', received '{fnd}'"
            ),
                None,
            ));
        }
        let fnd = url.path();
        let exp = authorization_endpoint.path();
        if fnd != exp {
            return Err(Error::protocol_invalid_req(
                &format!(
                    "unexpected authorization_endpoint path, expected '{exp}', received '{fnd}'"
                ),
                None,
            ));
        }
        Self::from_query_params(&query)
    }

    /// Parse from urlencoded query parameters.
    /// ```
    /// # use openid4vp::core::authorization_request::AuthorizationRequest;
    /// # use openid4vp::core::authorization_request::RequestIndirection;
    /// let query = "client_id=xyz&request=test";
    ///
    /// let AuthorizationRequest::Signed(authorization_request) = AuthorizationRequest::from_query_params(query).unwrap()
    /// else { panic!("expected signed authorization request") };
    ///
    /// assert_eq!(authorization_request.client_id, "xyz");
    ///
    /// let RequestIndirection::ByValue(request_object) = authorization_request.request_indirection
    /// else { panic!("expected request-by-value") };
    /// assert_eq!(request_object, "test");
    /// ```
    pub fn from_query_params(query_params: &str) -> Result<Self, Error> {
        let query_map: serde_json::Map<String, serde_json::Value> =
            serde_urlencoded::from_str(query_params).map_err(|e| {
                Error::protocol_invalid_req(
                    "unable to parse Authorization Request from query params",
                    None,
                )
                .add_source(e.into())
            })?;

        let auth_req = if query_map.contains_key("request") | query_map.contains_key("request_uri")
        {
            let signed_req =
                serde_json::from_value(serde_json::Value::Object(query_map)).map_err(|e| {
                    Error::protocol_invalid_req(
                        "unable to parse Signed Authorization Request from query params",
                        None,
                    )
                    .add_source(e.into())
                })?;

            Self::Signed(signed_req)
        } else {
            let auth_req_obj = AuthorizationRequestObject::try_from(UntypedObject(query_map))?;

            Self::Plain(auth_req_obj)
        };

        Ok(auth_req)
    }
}

impl AuthorizationRequestObject {
    pub fn state(&self) -> Option<String> {
        self.inner
            .get::<State>()
            .transpose()
            .ok()
            .flatten()
            .map(|s| s.0)
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn get_transaction_data(&self) -> Option<TransactionData> {
        self.inner
            .get::<TransactionData>()
            .transpose()
            .ok()
            .flatten()
    }
    pub fn get_transaction_data_items(&self) -> Result<Option<Vec<TransactionDataItem>>, Error> {
        if let Some(td) = self.get_transaction_data() {
            let mut items = Vec::new();
            for item in td.0 {
                let item = TransactionDataItem::from_base64url_encoded(&item).map_err(|e| {
                    Error::protocol(
                        ErrorType::InvalidTransactionData,
                        &format!("The transaction data cannot be parsed: {}", e),
                        self.state(),
                    )
                })?;
                items.push(item);
            }

            Ok(Some(items))
        } else {
            Ok(None)
        }
    }

    pub async fn resolve_presentation_query<HC>(
        &self,
        http_client: &HC,
    ) -> Result<ResolvedPresentationQuery, Error>
    where
        HC: AsyncHttpClient + WasmNotSend + WasmNotSync,
    {
        match &self.presentation_query {
            PresentationQuery::DCQL(dcql) => Ok(ResolvedPresentationQuery::DCQL(dcql.clone())),
            PresentationQuery::PresentationDefinition(pdw) => match pdw {
                PresentationDefinitionIndirection::ByValue(pd) => Ok(
                    ResolvedPresentationQuery::PresentationDefinition(pd.clone()),
                ),
                PresentationDefinitionIndirection::ByReference(url) => {
                    let resp = http_client
                        .execute(create_get_request(&url, MIME_TYPE_JSON)?)
                        .await
                        .map_err(|e| Error::Internal(anyhow!(e)))?;

                    if !resp.status().is_success() {
                        return Err(Error::protocol(
                            InvalidPresentationDefinitionUri,
                            &format!(
                                "failed to get Presentation Definition: status_code={}",
                                resp.status().as_u16(),
                            ),
                            self.state(),
                        ));
                    }

                    let presentation_def = serde_json::from_slice::<Json>(resp.body())
                        .map_err(|e| Error::internal(e.into()))?;
                    let presentation_def = PresentationDefinition::try_from(presentation_def)
                        .map_err(|e| {
                            Error::protocol(
                                InvalidPresentationDefinitionReference,
                                "failed to get parse Presentation Definition: {e}",
                                self.state(),
                            )
                            .add_source(e.into())
                        })?;
                    Ok(ResolvedPresentationQuery::PresentationDefinition(
                        presentation_def,
                    ))
                }
            },
        }
    }

    pub(crate) fn to_url(self, mut authorization_endpoint: Url) -> Result<Url, Error> {
        let query = serde_urlencoded::to_string(self.inner.flatten_for_form()?)
            .map_err(|e| Error::Internal(e.into()))?;

        authorization_endpoint.set_query(Some(&query));
        Ok(authorization_endpoint)
    }

    pub fn is_id_token_requested(&self) -> Option<bool> {
        match self.response_type {
            ResponseType::VpToken => Some(false),
            ResponseType::VpTokenIdToken => Some(true),
            ResponseType::Unsupported(_) => None,
        }
    }

    pub fn response_mode(&self) -> &ResponseMode {
        &self.response_mode
    }

    pub fn response_type(&self) -> &ResponseType {
        &self.response_type
    }

    /// Uri to submit the response at.
    ///
    /// AKA [ResponseUri] or [RedirectUri] depending on [ResponseMode].
    pub fn return_uri(&self) -> &Url {
        &self.return_uri
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn client_metadata(&self) -> &ClientMetadata {
        &self.client_metadata
    }
}

impl From<AuthorizationRequestObject> for UntypedObject {
    fn from(value: AuthorizationRequestObject) -> Self {
        let mut inner = value.inner;
        inner.insert(value.client_id);
        inner
    }
}

impl TryFrom<UntypedObject> for AuthorizationRequestObject {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        let state = value
            .get::<State>()
            .and_then(|result| result.ok())
            .map(|s| s.0);
        let client_id: ClientId = value.get().parsing_error()?;
        let redirect_uri = value.get::<RedirectUri>();
        let response_uri = value.get::<ResponseUri>();

        let (return_uri, response_mode) = match (
            redirect_uri,
            response_uri,
            value.get_or_default::<ResponseMode>()?,
        ) {
            (Some(uri), None, mode @ ResponseMode::DCAPI | mode @ ResponseMode::DCAPIJwt) => (
                uri.parsing_error()
                    .map_err(|e| {
                        Error::protocol_invalid_req(
                            "could not parse a 'redirect_uri'",
                            state.clone(),
                        )
                        .add_source(e.into())
                    })?
                    .0,
                mode,
            ),
            (
                None,
                Some(uri),
                mode @ ResponseMode::DirectPost | mode @ ResponseMode::DirectPostJwt,
            ) => (
                uri.parsing_error()
                    .map_err(|e| {
                        Error::protocol_invalid_req(
                            "could not parse a 'response_uri'",
                            state.clone(),
                        )
                        .add_source(e.into())
                    })?
                    .0,
                mode,
            ),
            (_, _, ResponseMode::Unsupported(m)) => {
                return Err(Error::protocol_invalid_req(
                    &format!("'{m}' response_mode is not supported"),
                    state.clone(),
                ))
            }
            (Some(_), Some(_), _) => {
                return Err(Error::protocol_invalid_req(
                    "'response_uri' and 'redirect_uri' are mutually exclusive",
                    state.clone(),
                ))
            }
            (_, None, mode @ ResponseMode::DirectPost)
            | (_, None, mode @ ResponseMode::DirectPostJwt) => {
                return Err(Error::protocol_invalid_req(
                    &format!(
                        "'response_uri' is required for this '{}' response mode",
                        mode
                    ),
                    state.clone(),
                ))
            }
            (None, _, mode @ ResponseMode::DCAPI | mode @ ResponseMode::DCAPIJwt) => {
                return Err(Error::protocol_invalid_req(
                    &format!(
                        "'redirect_uri' is required for this '{}' response mode",
                        mode
                    ),
                    state.clone(),
                ))
            }
        };

        let response_type: ResponseType = value.get().parsing_error()?;

        let presentation_query = match (
            value.get::<PresentationDefinition>(),
            value.get::<PresentationDefinitionUri>(),
            value.get::<DCQL>(),
        ) {
            (None, None, Some(dcql)) => {
                let dcql_val = dcql.parsing_error().map_err(|e| Error::protocol(
                    InvalidDCQLFormat,
                    "an error occurred in parsing dcql_query", state.clone()
                ).add_source(e.into()))?;
                PresentationQuery::DCQL(dcql_val)
            }
            (Some(pd), None, None) => {
                let pd_val = pd.parsing_error().map_err(|e| Error::protocol(
                    InvalidPresentationDefinitionFormat,
                    "an error occurred in parsing presentation_definition", state.clone()
                ).add_source(e.into()))?;
                PresentationQuery::PresentationDefinition(PresentationDefinitionIndirection::ByValue(pd_val))
            }
            (None, Some(by_reference), None) => {
                let url = by_reference.parsing_error().map_err(|e| Error::protocol(
                    InvalidPresentationDefinitionUri,
                    "could parse a 'presentation_definition_uri'", state.clone()
                ).add_source(e.into()))?.0;
                PresentationQuery::PresentationDefinition(PresentationDefinitionIndirection::ByReference(url))
            }
            _ => return Err(Error::protocol_invalid_req(
                "one and only one correctly formatted of 'presentation_definition', 'presentation_definition_uri' or 'dcql_query' is required", state.clone())),
        };

        let nonce = value.get().parsing_error()?;
        let client_metadata = value.get().parsing_error()?;

        Ok(Self {
            inner: value,
            client_id,
            response_mode,
            response_type,
            presentation_query,
            return_uri,
            nonce,
            client_metadata,
        })
    }
}

impl Deref for AuthorizationRequestObject {
    type Target = UntypedObject;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for AuthorizationRequestObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl SignedAuthorizationRequest {
    /// Try to resolve `response_uri`.
    pub async fn resolve_response_uri_and_mode<W>(
        &self,
        wallet: &W,
    ) -> Result<(Url, ResponseMode), Error>
    where
        W: Wallet,
    {
        let jwt = self.retrieve_unverified_jwt(wallet).await?;

        let aro: AuthorizationRequestObject =
            ssi::claims::jwt::decode_unverified::<UntypedObject>(&jwt)
                .map_err(|e| {
                    Error::internal(anyhow!(
                        "unable to decode Authorization Request Object JWT: {e}"
                    ))
                })?
                .try_into()?;

        self.validate_nonce(wallet, &aro).await?;

        Ok((aro.return_uri().to_owned(), aro.response_mode().to_owned()))
    }

    pub(crate) fn to_url(self, mut authorization_endpoint: Url) -> Result<Url, Error> {
        let query = serde_urlencoded::to_string(self).map_err(|e| Error::Internal(e.into()))?;

        authorization_endpoint.set_query(Some(&query));
        Ok(authorization_endpoint)
    }

    async fn resolve_auth_request<W>(&self, wallet: &W) -> Result<AuthorizationRequestObject, Error>
    where
        W: Wallet + ?Sized,
    {
        let unverified_jwt = self.retrieve_unverified_jwt(wallet).await?;
        let fetched_auth_req = FetchedAuthorizationRequest::UnverifiedJwt(unverified_jwt);

        let aro = verify_request(wallet, fetched_auth_req).await?;
        self.validate_nonce(wallet, &aro).await?;
        let state = aro.state();
        if self.client_id.as_str() != aro.client_id().get_full_id().as_str() {
            return Err(Error::protocol_invalid_req(
                &format!(
                    "Authorization Request and Request Object have different client ids: '{}' vs. '{}'",
                    self.client_id,
                    aro.client_id().get_full_id()
                ),
                state.clone(),
            ));
        }

        Ok(aro)
    }

    async fn retrieve_unverified_jwt<W>(&self, wallet: &W) -> Result<String, Error>
    where
        W: Wallet + ?Sized,
    {
        match &self.request_indirection {
            RequestIndirection::ByValue(jwt) => Ok(jwt.to_owned()),
            RequestIndirection::ByReference(request_reference) => {
                self.get_by_reference(wallet, request_reference).await
            }
        }
    }

    async fn get_by_reference<W>(
        &self,
        wallet: &W,
        request_reference: &RequestReference,
    ) -> Result<String, Error>
    where
        W: Wallet + ?Sized,
    {
        let method = request_reference
            .request_uri_method
            .clone()
            .unwrap_or(HttpMethodForAuth::GET);
        let resp = match method {
            HttpMethodForAuth::GET => wallet
                .http_client()
                .execute(create_get_request(
                    &request_reference.request_uri,
                    MIME_TYPE_OAUTH_REQ_JWT,
                )?)
                .await
                .map_err(|e| Error::Internal(anyhow!(e)))?,
            HttpMethodForAuth::POST => {
                let encoded_metadata: String = serde_json::to_string(&wallet.metadata())
                    .map_err(|e| Error::Internal(e.into()))
                    .map(|v| byte_serialize(v.as_bytes()).collect())?;
                let mut body = format!("wallet_metadata={}", encoded_metadata);
                if let Ok(Some(nonce)) = wallet.generate_nonce().await {
                    body = format!("{}&wallet_nonce={}", body, nonce.0);
                }
                let body_as_bytes = body.as_bytes().to_vec();
                wallet
                    .http_client()
                    .execute(create_post_request(
                        &request_reference.request_uri,
                        &body_as_bytes,
                        MIME_TYPE_FORM_URLENCODED,
                        MIME_TYPE_OAUTH_REQ_JWT,
                    )?)
                    .await
                    .map_err(|e| Error::Internal(anyhow!(e)))?
            }
        };
        Self::http_resp_to_unverified_jwt(resp)
    }

    async fn validate_nonce<W>(
        &self,
        wallet: &W,
        aro: &AuthorizationRequestObject,
    ) -> Result<(), Error>
    where
        W: Wallet + ?Sized,
    {
        let wallet_nonce = aro.get::<WalletNonce>().transpose()?;
        if let Some(nonce) = wallet_nonce {
            let valid = wallet.validate_nonce(&nonce).await?;
            if !valid {
                return Err(Error::protocol(
                    ErrorType::InvalidRequest,
                    "wallet_nonce validation did not pass",
                    None,
                ));
            }
        }
        Ok(())
    }

    fn http_resp_to_unverified_jwt(resp: Response<Vec<u8>>) -> Result<String, Error> {
        if !resp.status().is_success() {
            return Err(Error::internal(anyhow!(
                "failed to get authorization request object"
            )));
        }

        let jwt = String::from_utf8(resp.body().to_owned()).map_err(|e| {
            Error::internal(anyhow!("cannot parse authorization request object: {e}"))
        })?;

        Ok(jwt)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::authorization_request::AuthorizationRequestObject;
    use serde_json::json;

    #[test]
    fn test_authorization_request_object_deserialize_successfully() {
        let json = get_json_for_presentation_definition();
        println!("{:?}", json);
        let json = get_json_for_presentation_definition_uri();
        println!("{:?}", json);
        let json = get_json_for_dcql();
        println!("{:?}", json);
    }

    #[test]
    #[should_panic(
        expected = "invalid_request:one and only one correctly formatted of 'presentation_definition', 'presentation_definition_uri' or 'dcql_query' is required"
    )]
    fn test_authorization_request_object_deserialize_error() {
        let json = get_json_for_wrong_authorization_request_object();
        println!("{:?}", json);
    }

    fn get_json_for_presentation_definition() -> AuthorizationRequestObject {
        serde_json::from_value(json!({
          "response_type": "vp_token",
          "client_id": "redirect_uri:https://verifier.example.org",
          "redirect_uri": "https://verifier.example.org/callback",
          "scope": "openid",
          "nonce": "n-0S6_WzA2Mj",
          "state": "af0ifjsldkj",
          "presentation_definition": {
            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
            "input_descriptors": [
              {
                "id": "citizenship_input",
                "name": "Citizenship Credential",
                "purpose": "We need to verify your citizenship status",
                "format": {
                  "jwt_vp": {
                    "alg": ["EdDSA", "ES256K"]
                  },
                  "jwt_vc": {
                    "alg": ["ES256K", "EdDSA"]
                  }
                },
                "constraints": {
                  "fields": [
                    {
                      "path": ["$.type"],
                      "filter": {
                        "type": "string",
                        "pattern": "CitizenshipCredential"
                      }
                    }
                  ]
                }
              }
            ]
          },
          "client_metadata": {
            "client_name": "Example Verifier",
            "logo_uri": "https://verifier.example.org/logo.png",
            "tos_uri": "https://verifier.example.org/tos",
            "policy_uri": "https://verifier.example.org/privacy",
            "client_uri": "https://verifier.example.org"
          },
          "response_mode": "dc_api",
          "exp": 1685694443,
          "iat": 1685693443
        }))
        .unwrap()
    }

    fn get_json_for_presentation_definition_uri() -> AuthorizationRequestObject {
        serde_json::from_value(
            json!({
              "response_type": "vp_token",
              "client_id": "redirect_uri:https://verifier.example.org",
              "redirect_uri": "https://verifier.example.org/callback",
              "scope": "openid",
              "nonce": "n-0S6_WzA2Mj",
              "state": "af0ifjsldkj",
              "presentation_definition_uri": "https://verifier.example.org/presentation-definitions/citizenship-verification",
              "client_metadata": {
                "client_name": "Example Verifier",
                "logo_uri": "https://verifier.example.org/logo.png",
                "tos_uri": "https://verifier.example.org/tos",
                "policy_uri": "https://verifier.example.org/privacy",
                "client_uri": "https://verifier.example.org"
              },
              "response_mode": "dc_api",
              "exp": 1685694443,
              "iat": 1685693443
        }))
            .unwrap()
    }

    fn get_json_for_dcql() -> AuthorizationRequestObject {
        serde_json::from_value(json!({
              "type": "vp_token",
              "client_id": "redirect_uri:https://verifier.example.org",
              "response_uri": "https://verifier.example.org/response",
              "response_type": "vp_token",
              "response_mode": "direct_post",
              "scope": "openid",
              "nonce": "n-0S6_WzA2Mj",
              "client_metadata": {
                "client_name": "Example Verifier",
                "client_purpose": "Verification of credentials",
                "logo_uri": "https://verifier.example.org/logo.png",
                "tos_uri": "https://verifier.example.org/tos",
                "client_uri": "https://verifier.example.org"
              },
              "dcql_query": {
               "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                      },
                      "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                      ]
                    },
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": [ "https://credentials.example.com/identity_credential" ]
                      },
                      "claims": [
                        {"id": "a", "path": ["last_name"]},
                        {"id": "d", "path": ["postal_code"]},
                        {"id": "c", "path": ["locality"]},
                        {"id": "3e", "path": ["region"]},
                        {"id": "3", "path": ["date_of_birth"]}
                      ],
                      "claim_sets": [
                        ["a", "c", "d", "e"],
                        ["a", "b", "e"]
                      ]
                    },
                    {
                      "id": "sdfs",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                      },
                      "claims": [
                        {
                          "namespace": "org.iso.7367.1",
                          "claim_name": "vehicle_holder"
                        },
                        {
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "first_name"
                        }
                      ]
                    },
                    {
                      "id": "dsadcsdfsd",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                      },
                      "claims": [
                        {
                          "namespace": "org.iso.7367.1",
                          "claim_name": "vehicle_holder"
                        },
                        {
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "first_name"
                        }
                      ]
                    }
                ],
        "credential_sets": [
            {
              "purpose": "Identification",
              "options": [
                [ "pid" ],
                [ "other_pid" ],
                [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
              ]
            },
            {
              "purpose": "Show your rewards card",
              "required": false,
              "options": [
                [ "nice_to_have" ]
              ]
            }
          ]
            },
              "state": "af0ifjsldkj"
        }))
        .unwrap()
    }

    fn get_json_for_wrong_authorization_request_object() -> AuthorizationRequestObject {
        serde_json::from_value(
            json!({
              "response_type": "vp_token",
              "client_id": "redirect_uri:https://verifier.example.org",
              "redirect_uri": "https://verifier.example.org/callback",
              "scope": "openid",
              "nonce": "n-0S6_WzA2Mj",
              "state": "af0ifjsldkj",
                "dcql_query": {
               "credentials": [
                    {
                        "id": "some id",
                       "format": "dc+sd-jwt",
                        "meta": {
                        "test": "test",
                    },
                    }
                ]
            },
              "presentation_definition_uri": "https://verifier.example.org/presentation-definitions/citizenship-verification",
              "client_metadata": {
                "client_name": "Example Verifier",
                "logo_uri": "https://verifier.example.org/logo.png",
                "tos_uri": "https://verifier.example.org/tos",
                "policy_uri": "https://verifier.example.org/privacy",
                "client_uri": "https://verifier.example.org"
              },
              "response_mode": "dc_api",
              "exp": 1685694443,
              "iat": 1685693443
        }))
            .unwrap()
    }
}

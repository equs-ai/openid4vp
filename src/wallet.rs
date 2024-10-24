use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use oauth2::{HttpRequest, HttpResponse};
use std::future::Future;
use tracing::warn;
use url::Url;

use crate::core::error::Error;
use crate::core::util::http::{create_post_request, MIME_TYPE_FORM_URLENCODED};
use crate::core::{
    authorization_request::{
        parameters::ResponseMode, verification::RequestVerifier, AuthorizationRequest,
        AuthorizationRequestObject,
    },
    metadata::WalletMetadata,
    response::{AuthorizationResponse, PostRedirection},
};

#[async_trait]
pub trait Wallet: RequestVerifier + Sync {
    fn metadata(&self) -> &WalletMetadata;
    async fn validate_request<HC, RE, F>(
        &self,
        url: &Url,
        http_client_fn: HC,
    ) -> Result<AuthorizationRequestObject, Error>
    where
        HC: Fn(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send + Sync,
    {
        let ar = AuthorizationRequest::from_url(url, &self.metadata().authorization_endpoint().0)
            .context("unable to parse authorization request")?;
        let auth_req_obj = ar
            .validate(self, http_client_fn)
            .await
            .context("unable to validate authorization request")?;

        Ok(auth_req_obj)
    }

    async fn submit_response<HC, RE, F>(
        &self,
        response_uri: &Url,
        response_mode: &ResponseMode,
        response: AuthorizationResponse,
        http_client_fn: HC,
    ) -> Result<Option<Url>, Error>
    where
        HC: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send + Sync,
    {
        let http_request = match response_mode {
            ResponseMode::DirectPost => {
                let AuthorizationResponse::Unencoded(un_encoded) = response else {
                    return Err(Error::internal(anyhow!(
                        "unexpected AuthorizationResponse format"
                    )));
                };
                let body = un_encoded.into_x_www_form_urlencoded()?.into_bytes();

                create_post_request(response_uri, &body, MIME_TYPE_FORM_URLENCODED)
            }
            ResponseMode::DirectPostJwt => {
                let AuthorizationResponse::Jwt(jwt) = response else {
                    return Err(Error::internal(anyhow!(
                        "unexpected AuthorizationResponse format"
                    )));
                };
                let body = jwt.into_x_www_form_urlencoded()?.into_bytes();

                create_post_request(response_uri, &body, MIME_TYPE_FORM_URLENCODED)
            }
            ResponseMode::Unsupported(rm) => {
                return Err(Error::internal(anyhow!("unsupported response_mode {rm}")))
            }
        };

        let http_response = http_client_fn(http_request)
            .await
            .context("failed to make authorization response request")?;

        let status = http_response.status_code;
        if !status.is_success() {
            return Err(Error::internal(anyhow!(
                "error submitting authorization response: status_code={}, response_body={}",
                status,
                String::from_utf8(http_response.body).unwrap_or("".to_owned())
            )));
        }

        Ok(serde_json::from_slice(&http_response.body)
            .map_err(|e| warn!("response did not contain a redirect: {e}"))
            .ok()
            .map(|PostRedirection { redirect_uri }| redirect_uri))
    }
}

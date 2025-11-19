use crate::core::authorization_request::parameters::{Nonce, WalletNonce};
use crate::core::error::Error;
use crate::core::response::parameters::IdTokenBody;
use crate::core::util::http::{
    create_post_request, AsyncHttpClient, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON,
};
use crate::core::{
    authorization_request::{
        parameters::ResponseMode, verification::RequestVerifier, AuthorizationRequest,
        AuthorizationRequestObject,
    },
    metadata::WalletMetadata,
    response::{AuthorizationResponse, PostRedirection},
};
use crate::signer::Signer;
use crate::utils::{generate_jwt, WasmNotSend, WasmNotSync};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde_json::json;
use tracing::warn;
use url::Url;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Wallet: RequestVerifier + WasmNotSync {
    type HttpClient: AsyncHttpClient + WasmNotSend + WasmNotSync;

    fn metadata(&self) -> &WalletMetadata;
    fn http_client(&self) -> &Self::HttpClient;

    /// We may be asked by the user to use wallet_nonce to counter replay attacks.
    /// Then [self.generate_nonce] and [self.validate_nonce] must be implemented by the corresponding holder that implements the Wallet trait.
    /// Another way to do the job may have been similar to how HttpClient type added and an implementation passed but
    /// The nonce generation/validation is optional and Option is not associated type.
    async fn generate_nonce(&self) -> Result<Option<WalletNonce>>;

    async fn validate_nonce(&self, nonce: &WalletNonce) -> Result<bool>;

    async fn validate_request(&self, url: &Url) -> Result<AuthorizationRequestObject, Error> {
        let ar = AuthorizationRequest::from_url(url, &self.metadata().authorization_endpoint().0)
            .context("unable to parse authorization request")?;
        let auth_req_obj = ar
            .validate(self)
            .await
            .context("unable to validate authorization request")?;

        Ok(auth_req_obj)
    }

    async fn submit_response(
        &self,
        response_uri: &Url,
        response_mode: &ResponseMode,
        response: AuthorizationResponse,
    ) -> Result<Option<Url>, Error> {
        let http_request = match response_mode {
            ResponseMode::DirectPost => {
                let AuthorizationResponse::Unencoded(un_encoded) = response else {
                    return Err(Error::internal(anyhow!(
                        "unexpected AuthorizationResponse format"
                    )));
                };
                let body = un_encoded.into_x_www_form_urlencoded()?.into_bytes();

                create_post_request(
                    response_uri,
                    &body,
                    MIME_TYPE_FORM_URLENCODED,
                    MIME_TYPE_JSON,
                )?
            }
            ResponseMode::DirectPostJwt => {
                let AuthorizationResponse::Jwt(jwt) = response else {
                    return Err(Error::internal(anyhow!(
                        "unexpected AuthorizationResponse format"
                    )));
                };
                let body = jwt.into_x_www_form_urlencoded()?.into_bytes();

                create_post_request(
                    response_uri,
                    &body,
                    MIME_TYPE_FORM_URLENCODED,
                    MIME_TYPE_JSON,
                )?
            }
            ResponseMode::Fragment | ResponseMode::FragmentJwt => {
                let AuthorizationResponse::Unencoded(un_encoded) = response else {
                    return Err(Error::internal(anyhow!(
                        "unexpected AuthorizationResponse format"
                    )));
                };

                let url_encoded = un_encoded.into_x_www_form_urlencoded()?;
                let mut redirect_url = response_uri.clone();
                redirect_url.set_fragment(Some(&url_encoded));

                return Ok(Some(redirect_url));
            }
            rm @ ResponseMode::DcApi | rm @ ResponseMode::DcApiJwt => {
                return Err(Error::internal(anyhow!(
                    "in response_mode {rm}, authorization response could not be submitted"
                )))
            }
            ResponseMode::Unsupported(rm) => {
                return Err(Error::internal(anyhow!("unsupported response_mode {rm}")))
            }
        };

        let http_response = self
            .http_client()
            .execute(http_request)
            .await
            .context("failed to make authorization response request")?;

        let status = http_response.status();
        if !status.is_success() {
            return Err(Error::internal(anyhow!(
                "error submitting authorization response: status_code={}, response_body={}",
                status,
                String::from_utf8(http_response.body().to_owned()).unwrap_or("".to_owned())
            )));
        }

        Ok(serde_json::from_slice(http_response.body())
            .map_err(|e| warn!("response did not contain a redirect: {e}"))
            .ok()
            .map(|PostRedirection { redirect_uri }| redirect_uri))
    }

    async fn generate_did_based_id_token<S>(
        &self,
        did_url: &ssi::dids::DIDURLBuf,
        params: IdTokenParams,
        signer: S,
    ) -> Result<String>
    where
        S: Signer + WasmNotSend + WasmNotSync,
    {
        let IdTokenParams {
            audience,
            nonce,
            lifetime,
            other,
        } = params;
        let now = time::OffsetDateTime::now_utc();
        let expiration_time = now + lifetime;

        let id_token = IdTokenBody {
            issuer: did_url.did().to_string(),
            subject: did_url.did().to_string(),
            audience,
            nonce: nonce.into(),
            other,
            expiration_time: expiration_time.unix_timestamp(),
            sub_jwk: None,
            issued_at: Some(now.unix_timestamp()),
        };

        let algorithm = signer
            .alg()
            .context("failed to retrieve signing algorithm")?;

        let header = json!({
            "alg": algorithm,
            "kid": did_url,
            "typ": "JWT"
        });

        generate_jwt(header, &id_token, &signer).await
    }
}

pub struct IdTokenParams {
    pub audience: String,
    pub nonce: Nonce,
    pub lifetime: time::Duration,
    pub other: Option<serde_json::Map<String, serde_json::Value>>,
}

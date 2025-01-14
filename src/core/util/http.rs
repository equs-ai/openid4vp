use std::str::FromStr;
use url::Url;

use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, Uri};

/// Generic HTTP client.
///
/// A trait is used here so to facilitate native HTTP/TLS when compiled for mobile applications.
#[async_trait]
pub trait AsyncHttpClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>>;
}

#[derive(Debug)]
pub struct ReqwestClient(reqwest::Client);

impl AsRef<reqwest::Client> for ReqwestClient {
    fn as_ref(&self) -> &reqwest::Client {
        &self.0
    }
}

impl ReqwestClient {
    pub fn new() -> Result<Self> {
        reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .context("unable to build http_client")
            .map(Self)
    }
}

#[async_trait]
impl AsyncHttpClient for ReqwestClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        let response = self
            .0
            .execute(request.try_into().context("unable to convert request")?)
            .await
            .context("http request failed")?;

        let mut builder = Response::builder()
            .status(response.status())
            .version(response.version());

        builder
            .extensions_mut()
            .context("unable to set extensions")?
            .extend(response.extensions().clone());

        builder
            .headers_mut()
            .context("unable to set headers")?
            .extend(response.headers().clone());

        builder
            .body(
                response
                    .bytes()
                    .await
                    .context("failed to extract response body")?
                    .to_vec(),
            )
            .context("unable to construct response")
    }
}

pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const MIME_TYPE_OAUTH_REQ_JWT: &str = "application/oauth-authz-req+jwt";
pub const MIME_TYPE_TEXT_PLAIN: &str = "text/plain";

pub fn create_post_request(
    url: &Url,
    body: &Vec<u8>,
    content_type: &str,
    accept: &str,
) -> Result<Request<Vec<u8>>> {
    let headers = match (
        HeaderValue::from_str(content_type),
        HeaderValue::from_str(accept),
    ) {
        (Ok(content_type), Ok(accept)) => vec![(CONTENT_TYPE, content_type), (ACCEPT, accept)],
        _ => vec![],
    };

    let request = Request::new(body);

    let (mut parts, body) = request.into_parts();
    parts.uri = Uri::from_str(url.as_str()).context("could not parse request uri")?;
    parts.method = Method::POST;
    parts.headers = HeaderMap::from_iter(headers);

    let req = Request::from_parts(parts, body.to_owned());

    Ok(req)
}

pub fn create_get_request(url: &Url, accept: &str) -> Result<Request<Vec<u8>>> {
    let headers = match HeaderValue::from_str(accept) {
        Ok(accept) => vec![(ACCEPT, accept)],
        _ => vec![],
    };
    let uri = Uri::from_str(url.as_str()).context("could not parse request uri")?;
    let request = Request::new(vec![]);

    let (mut parts, body) = request.into_parts();
    parts.uri = uri;
    parts.method = Method::GET;
    parts.headers = HeaderMap::from_iter(headers);

    let req = Request::from_parts(parts, body.to_owned());

    Ok(req)
}

#[cfg(test)]
mod test {
    use http::Response;

    #[test]
    fn debug() {
        Response::builder().extensions_mut().unwrap();
        Response::builder().headers_mut().unwrap();
    }
}

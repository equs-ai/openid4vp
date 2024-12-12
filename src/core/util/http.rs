use oauth2::http::header::ACCEPT;
use oauth2::http::{HeaderMap, Method};
use oauth2::{
    http::header::{HeaderValue, CONTENT_TYPE},
    HttpRequest,
};
use url::Url;

pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
pub const MIME_TYPE_TEXT_PLAIN: &str = "text/plain";

pub fn create_post_request(
    url: &Url,
    body: &Vec<u8>,
    content_type: &str,
    accept: &str,
) -> HttpRequest {
    let headers = match (
        HeaderValue::from_str(content_type),
        HeaderValue::from_str(accept),
    ) {
        (Ok(content_type), Ok(accept)) => vec![(CONTENT_TYPE, content_type), (ACCEPT, accept)],
        _ => vec![],
    };

    HttpRequest {
        url: url.to_owned(),
        method: Method::POST,
        headers: HeaderMap::from_iter(headers),
        body: body.to_owned(),
    }
}

pub fn create_get_request(url: &Url, accept: &str) -> HttpRequest {
    let headers = match HeaderValue::from_str(accept) {
        Ok(accept) => vec![(ACCEPT, accept)],
        _ => vec![],
    };

    HttpRequest {
        url: url.to_owned(),
        method: Method::GET,
        headers: HeaderMap::from_iter(headers),
        body: Default::default(),
    }
}

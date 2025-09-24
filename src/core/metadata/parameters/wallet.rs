use crate::core::{
    authorization_request::parameters::{ClientIdPrefix, ResponseType},
    object::TypedParameter,
};

use crate::core::metadata::parameters::VpFormatsSupported;
use anyhow::{bail, Error, Result};
use serde_json::Value as Json;
use url::Url;

#[derive(Debug, Clone)]
pub struct Issuer(pub String);

impl TypedParameter for Issuer {
    const KEY: &'static str = "issuer";
}

impl TryFrom<Json> for Issuer {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<Issuer> for Json {
    fn from(value: Issuer) -> Json {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEndpoint(pub Url);

impl TypedParameter for AuthorizationEndpoint {
    const KEY: &'static str = "authorization_endpoint";
}

impl TryFrom<Json> for AuthorizationEndpoint {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEndpoint> for Json {
    fn from(value: AuthorizationEndpoint) -> Json {
        Json::String(value.0.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ResponseTypesSupported(pub Vec<ResponseType>);

impl Default for ResponseTypesSupported {
    fn default() -> Self {
        Self(vec![ResponseType::VpToken])
    }
}

impl TypedParameter for ResponseTypesSupported {
    const KEY: &'static str = "response_types_supported";
}

impl TryFrom<Json> for ResponseTypesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<ResponseTypesSupported> for Json {
    fn from(value: ResponseTypesSupported) -> Json {
        Json::Array(
            value
                .0
                .iter()
                .cloned()
                .map(String::from)
                .map(Json::from)
                .collect(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct ClientIdPrefixesSupported(pub Vec<ClientIdPrefix>);

impl TypedParameter for ClientIdPrefixesSupported {
    const KEY: &'static str = "client_id_prefixes_supported";
}

impl TryFrom<Json> for ClientIdPrefixesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let Json::Array(xs) = value else {
            bail!("expected JSON array")
        };
        xs.into_iter()
            .map(Json::try_into)
            .collect::<Result<Vec<ClientIdPrefix>>>()
            .map(Self)
    }
}

impl From<ClientIdPrefixesSupported> for Json {
    fn from(value: ClientIdPrefixesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

impl Default for ClientIdPrefixesSupported {
    fn default() -> Self {
        Self(vec![ClientIdPrefix::PreRegistered])
    }
}

#[derive(Debug, Clone)]
pub struct RequestObjectSigningAlgValuesSupported(pub Vec<String>);

impl Default for RequestObjectSigningAlgValuesSupported {
    fn default() -> Self {
        Self(vec!["ES256".to_string()])
    }
}

impl TypedParameter for RequestObjectSigningAlgValuesSupported {
    const KEY: &'static str = "request_object_signing_alg_values_supported";
}

impl TryFrom<Json> for RequestObjectSigningAlgValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<RequestObjectSigningAlgValuesSupported> for Json {
    fn from(value: RequestObjectSigningAlgValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

impl TryFrom<VpFormatsSupported> for Json {
    type Error = Error;

    fn try_from(value: VpFormatsSupported) -> Result<Json, Self::Error> {
        serde_json::to_value(value.0).map_err(Into::into)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEncryptionAlgValuesSupported(pub Vec<String>);

impl TypedParameter for AuthorizationEncryptionAlgValuesSupported {
    const KEY: &'static str = "authorization_encryption_alg_values_supported";
}

impl TryFrom<Json> for AuthorizationEncryptionAlgValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEncryptionAlgValuesSupported> for Json {
    fn from(value: AuthorizationEncryptionAlgValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationEncryptionEncValuesSupported(pub Vec<String>);

impl TypedParameter for AuthorizationEncryptionEncValuesSupported {
    const KEY: &'static str = "authorization_encryption_enc_values_supported";
}

impl TryFrom<Json> for AuthorizationEncryptionEncValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<AuthorizationEncryptionEncValuesSupported> for Json {
    fn from(value: AuthorizationEncryptionEncValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone)]
pub struct IdTokenTypesSupported(pub Vec<String>);

impl Default for IdTokenTypesSupported {
    fn default() -> Self {
        Self(vec!["subject_signed_id_token".to_string()])
    }
}

impl TypedParameter for IdTokenTypesSupported {
    const KEY: &'static str = "id_token_types_supported";
}

impl TryFrom<Json> for IdTokenTypesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<IdTokenTypesSupported> for Json {
    fn from(value: IdTokenTypesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone)]
pub struct IdTokenSigningAlgValuesSupported(pub Vec<String>);

impl Default for IdTokenSigningAlgValuesSupported {
    fn default() -> Self {
        Self(vec!["ES256".to_string()])
    }
}

impl TypedParameter for IdTokenSigningAlgValuesSupported {
    const KEY: &'static str = "id_token_signing_alg_values_supported";
}

impl TryFrom<Json> for IdTokenSigningAlgValuesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<IdTokenSigningAlgValuesSupported> for Json {
    fn from(value: IdTokenSigningAlgValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone)]
pub struct ScopesSupported(pub Vec<String>);

impl Default for ScopesSupported {
    fn default() -> Self {
        Self(vec!["openid".to_string()])
    }
}

impl TypedParameter for ScopesSupported {
    const KEY: &'static str = "scopes_supported";
}

impl TryFrom<Json> for ScopesSupported {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<ScopesSupported> for Json {
    fn from(value: ScopesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::core::{
        credential_format::{ClaimFormatDesignation, ClaimFormatPayload},
        object::UntypedObject,
    };

    use super::*;

    fn metadata() -> UntypedObject {
        serde_json::from_value(json!({
            "issuer": "https://self-issued.me/v2",
            "authorization_endpoint": "mdoc-openid4vp://",
            "response_types_supported": [
                "vp_token"
            ],
            "vp_formats_supported":
            {
                "mso_mdoc": {
                }
            },
            "client_id_prefixes_supported": [
                "redirect_uri",
                "x509_hash"
            ],
            "request_object_signing_alg_values_supported": [
              "ES256"
            ],
            "authorization_encryption_alg_values_supported": [
              "ECDH-ES"
            ],
            "authorization_encryption_enc_values_supported": [
              "A256GCM"
            ],
            "scopes_supported": [
               "openid"
            ],
            "id_token_signing_alg_values_supported": [
               "ES256K",
               "EdDSA"
            ],
            "request_object_signing_alg_values_supported": [
               "ES256K",
               "EdDSA"
            ],
            "subject_syntax_types_supported": [
               "urn:ietf:params:oauth:jwk-thumbprint",
               "did:key"
            ],
            "id_token_types_supported": [
                "subject_signed_id_token"
            ]
        }
        ))
        .unwrap()
    }

    #[test]
    fn issuer() {
        let exp = "https://self-issued.me/v2";
        let Issuer(s) = metadata().get().unwrap().unwrap();
        assert_eq!(s, exp);
    }

    #[test]
    fn authorization_endpoint() {
        let exp = "mdoc-openid4vp://".parse().unwrap();
        let AuthorizationEndpoint(s) = metadata().get().unwrap().unwrap();
        assert_eq!(s, exp);
    }

    #[test]
    fn response_types_supported() {
        let exp = [ResponseType::VpToken];
        let ResponseTypesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    fn client_id_prefixes_supported() {
        let exp = [ClientIdPrefix::RedirectUri, ClientIdPrefix::X509Hash];
        let ClientIdPrefixesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    #[ignore]
    fn request_object_signing_alg_values_supported() {
        let exp = ["ES256".to_string()];
        let RequestObjectSigningAlgValuesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    fn vp_formats_supported() {
        let VpFormatsSupported(mut m) = metadata().get().unwrap().unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(
            m.remove(&ClaimFormatDesignation::MsoMDoc).unwrap(),
            ClaimFormatPayload::Json(serde_json::Value::Object(Default::default()))
        );
    }

    #[test]
    fn authorization_encryption_alg_values_supported() {
        let exp = ["ECDH-ES".to_string()];
        let AuthorizationEncryptionAlgValuesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }

    #[test]
    fn authorization_encryption_enc_values_supported() {
        let exp = ["A256GCM".to_string()];
        let AuthorizationEncryptionEncValuesSupported(v) = metadata().get().unwrap().unwrap();
        assert!(exp.iter().all(|x| v.contains(x)));
        assert!(v.iter().all(|x| exp.contains(x)));
    }
}

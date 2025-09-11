use crate::core::object::TypedParameter;

use anyhow::Error;
use serde::Deserialize;
use serde_json::{Map, Value as Json};

#[derive(Debug, Clone, Deserialize)]
pub struct JWKs {
    pub keys: Vec<Map<String, Json>>,
}

impl TypedParameter for JWKs {
    const KEY: &'static str = "jwks";
}

impl TryFrom<Json> for JWKs {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(Into::into)
    }
}

impl From<JWKs> for Json {
    fn from(value: JWKs) -> Json {
        let keys = value.keys.into_iter().map(Json::Object).collect();
        let mut obj = Map::default();
        obj.insert("keys".into(), Json::Array(keys));
        obj.into()
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedResponseEncValuesSupported(pub Vec<String>);
impl TypedParameter for EncryptedResponseEncValuesSupported {
    const KEY: &'static str = "encrypted_response_enc_values_supported";
}
impl TryFrom<Json> for EncryptedResponseEncValuesSupported {
    type Error = Error;
    fn try_from(value: Json) -> Result<EncryptedResponseEncValuesSupported, Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<EncryptedResponseEncValuesSupported> for Json {
    fn from(value: EncryptedResponseEncValuesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::String).collect())
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use crate::core::metadata::parameters::VpFormatsSupported;
    use crate::core::{
        credential_format::{ClaimFormatDesignation, ClaimFormatPayload},
        object::UntypedObject,
    };

    fn metadata() -> UntypedObject {
        serde_json::from_value(json!(
        {
            "jwks":{
               "keys":[
                  {
                     "kty":"EC",
                     "crv":"P-256",
                     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                     "use":"enc",
                     "kid":"1"
                  }
               ]
            },
            "vp_formats_supported":{ "mso_mdoc":{} }
        }
        ))
        .unwrap()
    }

    #[test]
    fn vp_formats() {
        let VpFormatsSupported(formats) = metadata().get().unwrap().unwrap();

        let mso_doc = formats
            .get(&ClaimFormatDesignation::MsoMDoc)
            .expect("failed to find mso doc");

        assert_eq!(
            mso_doc,
            &ClaimFormatPayload::Json(serde_json::Value::Object(Default::default()))
        )
    }

    #[test]
    fn jwks() {
        let JWKs { keys } = metadata().get().unwrap().unwrap();
        assert_eq!(keys.len(), 1);

        let jwk = &keys[0];
        assert_eq!(jwk.get("kty").unwrap(), "EC");
        assert_eq!(jwk.get("crv").unwrap(), "P-256");
        assert_eq!(
            jwk.get("x").unwrap(),
            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
        );
        assert_eq!(
            jwk.get("y").unwrap(),
            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        );
        assert_eq!(jwk.get("use").unwrap(), "enc");
        assert_eq!(jwk.get("kid").unwrap(), "1");
    }
}

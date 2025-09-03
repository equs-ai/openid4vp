use super::{object::UntypedObject, presentation_submission::PresentationSubmission};

use self::parameters::VpToken;
use crate::core::authorization_request::parameters::{HashAlgorithm, State};
use crate::core::object::ParsingErrorContext;
use crate::core::response::parameters::{IdToken, TransactionDataHashes, TransactionDataHashesAlg};
use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use url::Url;

pub mod parameters;

#[derive(Debug, Clone)]
pub enum AuthorizationResponse {
    Unencoded(UnencodedAuthorizationResponse),
    Jwt(JwtAuthorizationResponse),
}

impl AuthorizationResponse {
    pub fn from_x_www_form_urlencoded(bytes: &[u8]) -> Result<Self> {
        if let Ok(jwt) = serde_urlencoded::from_bytes(bytes) {
            return Ok(Self::Jwt(jwt));
        }

        let unencoded = serde_urlencoded::from_bytes::<JsonEncodedAuthorizationResponse>(bytes)
            .map_err(|_| anyhow!("failed to construct flat map"))?;

        Ok(Self::Unencoded(unencoded.try_into()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransactionDataResponse {
    pub transaction_data_hashes: TransactionDataHashes,
    pub transaction_data_hashes_alg: Option<TransactionDataHashesAlg>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JsonTransactionDataResponse {
    pub transaction_data_hashes: String,
    pub transaction_data_hashes_alg: Option<String>,
}
impl TryFrom<JsonTransactionDataResponse> for TransactionDataResponse {
    type Error = Error;
    fn try_from(value: JsonTransactionDataResponse) -> Result<Self> {
        let transaction_data_hashes = serde_json::from_str(&value.transaction_data_hashes)
            .map_err(|_| anyhow!("failed to serialize transaction_data_hashes"))?;
        let transaction_data_hashes_alg = if let Some(alg) = value.transaction_data_hashes_alg {
            let hash_alg = HashAlgorithm::try_from(alg).map_err(|_| {
                anyhow!("failed to convert transaction_data_hashes_alg to HashAlgorithm")
            })?;
            Some(TransactionDataHashesAlg(hash_alg))
        } else {
            None
        };
        Ok(TransactionDataResponse {
            transaction_data_hashes,
            transaction_data_hashes_alg,
        })
    }
}

impl TryFrom<TransactionDataResponse> for JsonTransactionDataResponse {
    type Error = Error;
    fn try_from(value: TransactionDataResponse) -> Result<Self> {
        let transaction_data_hashes = serde_json::to_string(&value.transaction_data_hashes)?;
        let transaction_data_hashes_alg = value
            .transaction_data_hashes_alg
            .map(|alg| serde_json::to_string(&alg.0))
            .transpose()?;
        Ok(Self {
            transaction_data_hashes,
            transaction_data_hashes_alg,
        })
    }
}
#[derive(Debug, Deserialize, Serialize)]
struct JsonEncodedAuthorizationResponse {
    /// `vp_token` is JSON string encoded.
    pub(crate) vp_token: String,
    /// `presentation_submission` is JSON string encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) presentation_submission: Option<String>,
    /// `id_token` is JSON string encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id_token: Option<String>,
    /// `state` is JSON string encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub(crate) transaction_data_response: Option<JsonTransactionDataResponse>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnencodedAuthorizationResponse {
    pub vp_token: VpToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<PresentationSubmission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<IdToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub transaction_data_response: Option<TransactionDataResponse>,
}

impl UnencodedAuthorizationResponse {
    /// Encode the Authorization Response as 'application/x-www-form-urlencoded'.
    pub fn into_x_www_form_urlencoded(self) -> Result<String> {
        let encoded = serde_urlencoded::to_string(JsonEncodedAuthorizationResponse::try_from(self)?)
            .map_err(|_| anyhow!("failed to encode UnencodedAuthorizationResponse as 'application/x-www-form-urlencoded'"))?;

        Ok(encoded)
    }

    /// Return the Verifiable Presentation Token.
    pub fn vp_token(&self) -> &VpToken {
        &self.vp_token
    }

    /// Return the Presentation Submission.
    pub fn presentation_submission(&self) -> Option<&PresentationSubmission> {
        self.presentation_submission.as_ref()
    }

    /// Return the Self Issued Id Token.
    pub fn id_token(&self) -> &Option<IdToken> {
        &self.id_token
    }

    /// Return the State.
    pub fn state(&self) -> &Option<String> {
        &self.state
    }
    pub fn transaction_data_response(&self) -> Option<&TransactionDataResponse> {
        self.transaction_data_response.as_ref()
    }
}

impl TryFrom<JsonEncodedAuthorizationResponse> for UnencodedAuthorizationResponse {
    type Error = Error;
    fn try_from(value: JsonEncodedAuthorizationResponse) -> Result<Self> {
        let vp_token: VpToken = serde_json::from_str(&value.vp_token)
            .map_err(|_| anyhow!("failed to decode vp token"))?;

        let presentation_submission = value
            .presentation_submission
            .map(|ps| serde_json::from_str(&ps))
            .transpose()?;
        let id_token = value
            .id_token
            .map(|jwt| IdToken::try_from(jwt).parsing_error())
            .transpose()?;

        let transaction_data_response = if let Some(tdr) = value.transaction_data_response {
            Some(tdr.try_into()?)
        } else {
            None
        };

        let state = value.state;
        Ok(UnencodedAuthorizationResponse {
            vp_token,
            presentation_submission,
            id_token,
            state,
            transaction_data_response,
        })
    }
}

impl TryFrom<UnencodedAuthorizationResponse> for JsonEncodedAuthorizationResponse {
    type Error = Error;
    fn try_from(value: UnencodedAuthorizationResponse) -> Result<Self> {
        let vp_token = value.vp_token.format_to_string();
        let presentation_submission = value
            .presentation_submission
            .and_then(|ps| serde_json::to_string(&ps).ok());
        let id_token = value.id_token.map(|i| i.jwt());
        let state = value.state;
        let transaction_data_response = if let Some(tdr) = value.transaction_data_response {
            Some(tdr.try_into()?)
        } else {
            None
        };
        Ok(Self {
            vp_token,
            presentation_submission,
            id_token,
            state,
            transaction_data_response,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuthorizationResponse {
    /// Can be JWT or JWE.
    pub response: String,
}

impl JwtAuthorizationResponse {
    /// Encode the Authorization Response as 'application/x-www-form-urlencoded'.
    pub fn into_x_www_form_urlencoded(self) -> Result<String> {
        serde_urlencoded::to_string(self).map_err(|_| {
            anyhow!("failed to encode response as 'application/x-www-form-urlencoded'")
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostRedirection {
    pub redirect_uri: Url,
}

impl TryFrom<UntypedObject> for UnencodedAuthorizationResponse {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        let vp_token = value.get().parsing_error()?;
        let presentation_submission = value
            .get()
            .transpose()
            .map_err(|e| anyhow!(format!("Error getting presentation_submission: {}", e)))?;
        let id_token = value
            .get::<IdToken>()
            .transpose()
            .map_err(|e| anyhow!(format!("Error getting id_token: {}", e)))?;

        let state = value
            .get::<State>()
            .transpose()
            .map_err(|e| anyhow!(format!("Error getting state: {}", e)))?
            .map(|state| state.0);
        let transaction_data_hashes = value
            .get::<TransactionDataHashes>()
            .transpose()
            .map_err(|e| anyhow!(format!("Error getting transaction_data_hashes: {}", e)))?;
        let transaction_data_hashes_alg = value
            .get::<TransactionDataHashesAlg>()
            .transpose()
            .map_err(|e| anyhow!(format!("Error getting transaction_data_hashes_alg: {}", e)))?;

        let transaction_data_response =
            transaction_data_hashes.map(|tdh| TransactionDataResponse {
                transaction_data_hashes: tdh,
                transaction_data_hashes_alg,
            });

        Ok(Self {
            vp_token,
            presentation_submission,
            id_token,
            state,
            transaction_data_response,
        })
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::core::object::UntypedObject;

    use super::{JwtAuthorizationResponse, UnencodedAuthorizationResponse};

    #[test]
    fn jwt_authorization_response_to_form_urlencoded() {
        let response = JwtAuthorizationResponse {
            response: "header.body.signature".into(),
        };
        assert_eq!(
            response.into_x_www_form_urlencoded().unwrap(),
            "response=header.body.signature",
        )
    }

    #[test]
    fn unencoded_authorization_response_to_form_urlencoded() {
        let object: UntypedObject = serde_json::from_value(json!(
            {
                "presentation_submission": {
                    "id": "d05a7f51-ac09-43af-8864-e00f0175f2c7",
                    "definition_id": "f619e64a-8f80-4b71-8373-30cf07b1e4f2",
                    "descriptor_map": []
                },
                "vp_token": "string",
                "transaction_data_hashes_alg": "sha-512",
                "transaction_data_hashes": ["hash1", "hash2"],
                "state": "some_state",
            }
        ))
        .unwrap();
        let response = UnencodedAuthorizationResponse::try_from(object).unwrap();
        let url_encoded = response.into_x_www_form_urlencoded().unwrap();

        assert!(url_encoded.contains("presentation_submission=%7B%22id%22%3A%22d05a7f51-ac09-43af-8864-e00f0175f2c7%22%2C%22definition_id%22%3A%22f619e64a-8f80-4b71-8373-30cf07b1e4f2%22%2C%22descriptor_map%22%3A%5B%5D%7D"));
        assert!(url_encoded.contains("vp_token=string"));
        assert!(url_encoded.contains("state=some_state"));
        println!("{}", url_encoded);
        assert!(url_encoded.contains("transaction_data_hashes_alg=%22sha-512%22"));
    }

    #[test]
    fn test() {
        let s = r#"hello there you &transaction_data_hashes_alg="sha-256""#;
        assert!(s.contains(r#"transaction_data_hashes_alg="sha-256""#));
    }
}

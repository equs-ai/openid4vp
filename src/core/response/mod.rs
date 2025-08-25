use super::{object::UntypedObject, presentation_submission::PresentationSubmission};

use self::parameters::VpToken;
use crate::core::authorization_request::parameters::State;
use crate::core::object::ParsingErrorContext;
use crate::core::response::parameters::{IdToken, TransactionDataHashes, TransactionDataHashesAlg};
use anyhow::{Context, Error, Result};
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
            .context("failed to construct flat map")?;

        Ok(Self::Unencoded(unencoded.try_into()?))
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
    /// `transaction_data_hashes` is JSON vec encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) transaction_data_hashes: Option<String>,
    /// `transaction_data_hashes_alg` is JSON string encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) transaction_data_hashes_alg: Option<String>,
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
    pub transaction_data_hashes: Option<TransactionDataHashes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<String>,
    
}

impl UnencodedAuthorizationResponse {
    /// Encode the Authorization Response as 'application/x-www-form-urlencoded'.
    pub fn into_x_www_form_urlencoded(self) -> Result<String> {
        let encoded = serde_urlencoded::to_string(JsonEncodedAuthorizationResponse::from(self))
            .context(
                "failed to encode presentation_submission as 'application/x-www-form-urlencoded'",
            )?;

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
    pub fn transaction_data_hashes(&self) -> Option<&TransactionDataHashes> {self.transaction_data_hashes.as_ref()}
    pub fn transaction_data_hashes_alg(&self) -> Option<&String> {self.transaction_data_hashes_alg.as_ref()}
    
}

impl TryFrom<JsonEncodedAuthorizationResponse> for UnencodedAuthorizationResponse {
    type Error = Error;
    fn try_from(value: JsonEncodedAuthorizationResponse) -> Result<Self> {
        let vp_token: VpToken =
            serde_json::from_str(&value.vp_token).context("failed to decode vp token")?;

        let presentation_submission = value
            .presentation_submission
            .map(|ps| serde_json::from_str(&ps))
            .transpose()?;
        let id_token = value
            .id_token
            .map(|jwt| IdToken::try_from(jwt).parsing_error())
            .transpose()?;

        let state = value.state;
        let transaction_data_hashes = value
            .transaction_data_hashes
            .map(|tdh| serde_json::from_str(&tdh))
            .transpose()?;
        let transaction_data_hashes_alg = value
            .transaction_data_hashes_alg;
    
        Ok(UnencodedAuthorizationResponse{
            vp_token,
            presentation_submission,
            id_token,
            state,
            transaction_data_hashes,
            transaction_data_hashes_alg,
        })
    }
}

impl From<UnencodedAuthorizationResponse> for JsonEncodedAuthorizationResponse {
    fn from(value: UnencodedAuthorizationResponse) -> Self {
        let vp_token = value.vp_token.format_to_string();

        let presentation_submission = value
            .presentation_submission
            .and_then(|ps| serde_json::to_string(&ps).ok());
        let id_token = value.id_token.map(|i| i.jwt());
        let state = value.state;

        let transaction_data_hashes = value.transaction_data_hashes
            .and_then(|tdh| serde_json::to_string(&tdh).ok());
        let transaction_data_hashes_alg = value.transaction_data_hashes_alg;
        Self {
            vp_token,
            presentation_submission,
            id_token,
            state,
            transaction_data_hashes,
            transaction_data_hashes_alg
        }
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
        serde_urlencoded::to_string(self)
            .context("failed to encode response as 'application/x-www-form-urlencoded'")
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
        let presentation_submission = value.get().parsing_error().ok();
        let id_token = value
            .get::<IdToken>()
            .map(|value| value.parsing_error())
            .transpose()?;

        let state = value
            .get::<State>()
            .map(|value| value.parsing_error())
            .transpose()?
            .map(|state| state.0);
        let transaction_data_hashes = value
            .get::<TransactionDataHashes>()
            .map(|value| value.parsing_error())
            .transpose()?;
        let transaction_data_hashes_alg = value
            .get::<TransactionDataHashesAlg>()
            .map(|value| value.parsing_error())
            .transpose()?
            .map(|tdha| tdha.0);

        Ok(Self {
            vp_token,
            presentation_submission,
            id_token,
            state,
            transaction_data_hashes,
            transaction_data_hashes_alg,
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
                "transaction_data_hashes_alg": "some",
                "transaction_data_hashes": ["fdsf", "assadasdsa"],
                "state": "some_state",
            }
        ))
        .unwrap();
        let response = UnencodedAuthorizationResponse::try_from(object).unwrap();
        let url_encoded = response.into_x_www_form_urlencoded().unwrap();

        assert!(url_encoded.contains("presentation_submission=%7B%22id%22%3A%22d05a7f51-ac09-43af-8864-e00f0175f2c7%22%2C%22definition_id%22%3A%22f619e64a-8f80-4b71-8373-30cf07b1e4f2%22%2C%22descriptor_map%22%3A%5B%5D%7D"));
        assert!(url_encoded.contains("vp_token=string"));
        assert!(url_encoded.contains("state=some_state"));
        assert!(url_encoded.contains("transaction_data_hashes_alg=some"));
    }
}

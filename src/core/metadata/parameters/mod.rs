use crate::core::credential_format::{ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload};
use crate::core::object::TypedParameter;
use anyhow::Error;
use serde_json::Value as Json;

/// Metadata supplied by the verifier, also known as the Client Metadata.
pub mod verifier;
/// Metadata supplied by the wallet, also known as the Authorization Server Metadata.
pub mod wallet;

#[derive(Debug, Clone)]
pub struct SubjectSyntaxTypesSupported(pub Vec<String>);

impl Default for SubjectSyntaxTypesSupported {
    fn default() -> Self {
        Self(vec![
            "urn:ietf:params:oauth:jwk-thumbprint".to_string(),
            "did:key".to_string(),
        ])
    }
}

impl SubjectSyntaxTypesSupported {
    pub fn contains(&self, sub_syntax_type: &String) -> bool {
        self.0.contains(sub_syntax_type)
    }
}

impl TypedParameter for SubjectSyntaxTypesSupported {
    const KEY: &'static str = "subject_syntax_types_supported";
}

impl TryFrom<Json> for SubjectSyntaxTypesSupported {
    type Error = Error;

    fn try_from(value: Json) -> anyhow::Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<SubjectSyntaxTypesSupported> for Json {
    fn from(value: SubjectSyntaxTypesSupported) -> Json {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone, Default)]
pub struct VpFormatsSupported(pub ClaimFormatMap);

impl TypedParameter for VpFormatsSupported {
    const KEY: &'static str = "vp_formats_supported";
}

impl TryFrom<Json> for VpFormatsSupported {
    type Error = Error;

    fn try_from(value: Json) -> anyhow::Result<Self, Self::Error> {
        serde_json::from_value(value).map(Self).map_err(Into::into)
    }
}

impl VpFormatsSupported {
    pub fn is_claim_format_supported(&self, designation: &ClaimFormatDesignation) -> bool {
        self.0.contains_key(designation)
    }

    pub fn contains_claim_format_with_payload(
        &self,
        designation: &ClaimFormatDesignation,
        payload: &ClaimFormatPayload,
    ) -> bool {
        if let Some(claim_payload) = self.0.get(designation) {
            return claim_payload.contains(payload);
        }

        false
    }

    /// Returns a boolean to denote whether a particular pair of format and security method
    /// are supported in the VP formats. A security method could be a JOSE algorithm, a COSE
    /// algorithm, a Cryptosuite, etc.
    ///
    /// NOTE: This method is interested in the security method of the claim format
    /// payload and not the claim format designation.
    ///
    /// For example, the security method would need to match one of the `alg`
    /// values in the claim format payload.
    pub fn supports_security_method(
        &self,
        format: &ClaimFormatDesignation,
        security_method: &String,
    ) -> bool {
        match self.0.get(format) {
            Some(ClaimFormatPayload::Alg(alg_values))
            | Some(ClaimFormatPayload::AlgValuesSupported(alg_values)) => {
                alg_values.contains(security_method)
            }
            Some(ClaimFormatPayload::ProofType(proof_types)) => {
                proof_types.contains(security_method)
            }
            _ => false,
        }
    }
}

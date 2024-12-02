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
        Self(vec!["urn:ietf:params:oauth:jwk-thumbprint".to_string(), "did:key".to_string()])
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

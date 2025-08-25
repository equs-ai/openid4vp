pub use crate::core::authorization_request::parameters::State;
use crate::core::object::TypedParameter;

use anyhow::{bail, Error};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use ssi::{
    claims::vc::{self, v2::SpecializedJsonCredential},
    json_ld::syntax::Object,
    one_or_many::OneOrManyRef,
    prelude::{AnyDataIntegrity, AnyJsonPresentation, AnySuite, DataIntegrity},
    OneOrMany, JWK,
};

#[derive(Debug, Clone)]
pub struct IdToken {
    raw: String,
    parsed: IdTokenBody,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IdTokenBody {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "aud")]
    pub audience: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_jwk: Option<JWK>,
    #[serde(rename = "iat")]
    pub issued_at: Option<i64>,
    #[serde(rename = "exp")]
    pub expiration_time: i64,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub other: Option<Map<String, Json>>,
}

impl IdToken {
    pub fn parsed_body(self) -> IdTokenBody {
        self.parsed
    }

    pub fn jwt(self) -> String {
        self.raw
    }
}

impl TypedParameter for IdToken {
    const KEY: &'static str = "id_token";
}

impl TryFrom<Json> for IdToken {
    type Error = Error;

    fn try_from(raw: Json) -> Result<Self, Self::Error> {
        let Json::String(raw) = raw else {
            bail!("IdToken must be json string")
        };
        let parsed = ssi::claims::jwt::decode_unverified(&raw)?;

        Ok(Self { raw, parsed })
    }
}

impl TryFrom<String> for IdToken {
    type Error = Error;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let parsed = ssi::claims::jwt::decode_unverified(&raw)?;

        Ok(Self { raw, parsed })
    }
}

impl From<IdToken> for Json {
    fn from(value: IdToken) -> Self {
        Json::String(value.raw)
    }
}

impl Serialize for IdToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let jwt = String::deserialize(deserializer)?;
        IdToken::try_from(jwt).map_err(serde::de::Error::custom)
    }
}

/// OpenID Connect for Verifiable Presentations specification defines `vp_token` parameter:
///
/// > JSON String or JSON object that MUST contain a single Verifiable Presentation or
/// > an array of JSON Strings and JSON objects each of them containing a Verifiable Presentations.
/// >
/// > Each Verifiable Presentation MUST be represented as a JSON string (that is a Base64url encoded value)
/// > or a JSON object depending on a format as defined in Appendix A of [OpenID.VCI].
/// >
/// > If Appendix A of [OpenID.VCI] defines a rule for encoding the respective Credential
/// > format in the Credential Response, this rules MUST also be followed when encoding Credentials of
/// > this format in the vp_token response parameter. Otherwise, this specification does not require
/// > any additional encoding when a Credential format is already represented as a JSON object or a JSON string.
///
/// See: [OpenID.VP#section-6.1-2.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.2)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VpToken(pub Vec<VpTokenItem>);

impl VpToken {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, VpTokenItem> {
        self.0.iter()
    }

    pub fn format_to_string(&self) -> String {
        let mut vp_token = serde_json::to_string(&self)
            // SAFTEY: VP Token will always be a valid JSON object.
            .unwrap();

        if self.0.len() == 1 {
            if let VpTokenItem::String(_) = &self.0[0] {
                vp_token = vp_token.trim_matches('"').to_string();
            }
        }

        vp_token
    }
}

impl TypedParameter for VpToken {
    const KEY: &'static str = "vp_token";
}

impl Serialize for VpToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OneOrManyRef::from_slice(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VpToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        OneOrMany::<VpTokenItem>::deserialize(deserializer)
            .map(OneOrMany::into_vec)
            .map(Self)
    }
}

impl From<VpTokenItem> for VpToken {
    fn from(value: VpTokenItem) -> Self {
        Self(vec![value])
    }
}

impl From<String> for VpToken {
    fn from(value: String) -> Self {
        Self(vec![value.into()])
    }
}

impl From<vc::v1::syntax::JsonPresentation> for VpToken {
    fn from(value: vc::v1::syntax::JsonPresentation) -> Self {
        Self(vec![value.into()])
    }
}

impl From<vc::v2::syntax::JsonPresentation> for VpToken {
    fn from(value: vc::v2::syntax::JsonPresentation) -> Self {
        Self(vec![value.into()])
    }
}

impl From<vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>> for VpToken {
    fn from(value: vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>) -> Self {
        Self(vec![value.into()])
    }
}

impl From<AnyJsonPresentation> for VpToken {
    fn from(value: AnyJsonPresentation) -> Self {
        Self(vec![value.into()])
    }
}

impl TryFrom<Json> for VpToken {
    type Error = anyhow::Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(Into::into)
    }
}

impl From<VpToken> for Json {
    fn from(value: VpToken) -> Self {
        serde_json::to_value(value)
            // SAFETY: a vp token has a valid JSON representation by definition.
            .unwrap()
    }
}

impl<'a> IntoIterator for &'a VpToken {
    type IntoIter = std::slice::Iter<'a, VpTokenItem>;
    type Item = &'a VpTokenItem;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for VpToken {
    type IntoIter = std::vec::IntoIter<VpTokenItem>;
    type Item = VpTokenItem;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VpTokenItem {
    String(String),
    JsonObject(serde_json::Map<String, serde_json::Value>),
}

impl From<String> for VpTokenItem {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<AnyDataIntegrity> for VpTokenItem {
    fn from(value: AnyDataIntegrity) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(&value)
            // SAFETY: by definition a Data Integrity Object is a Json LD Node and is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a Data Integrity Object is a Json LD Node and is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<vc::v1::syntax::JsonPresentation> for VpTokenItem {
    fn from(value: vc::v1::syntax::JsonPresentation) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<vc::v2::syntax::JsonPresentation> for VpTokenItem {
    fn from(value: vc::v2::syntax::JsonPresentation) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>> for VpTokenItem {
    fn from(value: vc::v2::syntax::JsonPresentation<SpecializedJsonCredential<Object>>) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<AnyJsonPresentation> for VpTokenItem {
    fn from(value: AnyJsonPresentation) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

impl From<DataIntegrity<AnyJsonPresentation, AnySuite>> for VpTokenItem {
    fn from(value: DataIntegrity<AnyJsonPresentation, AnySuite>) -> Self {
        let serde_json::Value::Object(obj) = serde_json::to_value(value)
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            .unwrap()
        else {
            // SAFETY: by definition a VCDM2.0 presentation is a JSON object.
            unreachable!()
        };

        Self::JsonObject(obj)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDataHashes(pub Vec<String>);

impl TypedParameter for TransactionDataHashes {
    const KEY: &'static str = "transaction_data_hashes";
}

impl TryFrom<Json> for TransactionDataHashes {
    type Error = Error;
    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<TransactionDataHashes> for Json {
    fn from(value: TransactionDataHashes) -> Self {
        Json::Array(value.0.into_iter().map(Json::from).collect())
    }
}

#[derive(Debug, Clone)]
pub struct TransactionDataHashesAlg(pub String);

impl TypedParameter for TransactionDataHashesAlg {
    const KEY: &'static str = "transaction_data_hashes_alg";
}

impl TryFrom<Json> for TransactionDataHashesAlg {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}
impl From<TransactionDataHashesAlg> for Json {
    fn from(value: TransactionDataHashesAlg) -> Self {
        Json::String(value.0)
    }
}
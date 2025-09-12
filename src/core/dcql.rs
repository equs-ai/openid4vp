use crate::core::credential_format::ClaimFormatDesignation;
use crate::core::object::TypedParameter;
use crate::utils::from_string_or_value;
use anyhow::{ensure, Error};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as Json;
use std::fmt::Debug;

const ID_REGEX: &str = r"^[a-zA-Z0-9_-]+$";

#[derive(Debug, Clone, PartialEq)]
pub struct ID(String);
impl ID {
    pub fn new(id: String) -> Result<ID, Error> {
        let regex = Regex::new(ID_REGEX)?;
        ensure!(
            regex.is_match(id.as_str()),
            "ID must only contain alphanumeric characters, hyphens, and underscores"
        );
        Ok(ID(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<Json> for ID {
    type Error = Error;
    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let parsed = from_string_or_value(&value)?;
        Ok(ID::new(parsed)?)
    }
}

impl TryFrom<ID> for Json {
    type Error = Error;
    fn try_from(value: ID) -> Result<Self, Self::Error> {
        Ok(value.0.into())
    }
}

impl TypedParameter for ID {
    const KEY: &'static str = "id";
}

impl Serialize for ID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ID::new(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct DCQL {
    credentials: Vec<DcqlCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_sets: Option<Vec<DcqlCredentialSet>>,
}

impl DCQL {
    pub fn new(credentials: Vec<DcqlCredential>) -> Self {
        Self {
            credentials,
            credential_sets: None,
        }
    }
    pub fn add_credential(mut self, credential: DcqlCredential) -> Self {
        self.credentials.push(credential);
        self
    }

    pub fn add_credential_sets(mut self, credential_set: DcqlCredentialSet) -> Self {
        if self.credential_sets.is_none() {
            self.credential_sets = Some(vec![credential_set]);
        } else {
            let mut sets = self
                .credential_sets
                .take()
                .expect("credential_sets missing");
            sets.push(credential_set);
            self.credential_sets = Some(sets);
        }
        self
    }

    pub fn credential_sets(&self) -> Option<&Vec<DcqlCredentialSet>> {
        self.credential_sets.as_ref()
    }
    pub fn credentials(&self) -> &Vec<DcqlCredential> {
        &self.credentials
    }
}

impl TryFrom<Json> for DCQL {
    type Error = Error;

    fn try_from(raw: Json) -> Result<Self, Self::Error> {
        let parsed = from_string_or_value(&raw)?;

        Ok(parsed)
    }
}

impl From<DCQL> for Json {
    fn from(value: DCQL) -> Self {
        // the format must be correct
        serde_json::to_value(value).unwrap()
    }
}

impl TypedParameter for DCQL {
    const KEY: &'static str = "dcql_query";
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DcqlCredential {
    id: ID,
    format: ClaimFormatDesignation,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<Meta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<Vec<DcqlClaim>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_sets: Option<Vec<Vec<String>>>,
}

impl DcqlCredential {
    pub fn new(id: ID, format: ClaimFormatDesignation) -> Self {
        Self {
            id,
            format,
            meta: None,
            claims: None,
            claim_sets: None,
        }
    }

    pub fn id(&self) -> &ID {
        &self.id
    }
    pub fn set_id(mut self, id: ID) -> Self {
        self.id = id;
        self
    }

    pub fn format(&self) -> &ClaimFormatDesignation {
        &self.format
    }
    pub fn set_format(mut self, format: ClaimFormatDesignation) -> Self {
        self.format = format;
        self
    }

    pub fn set_meta(mut self, meta: Meta) -> Self {
        self.meta = Some(meta);
        self
    }
    pub fn meta(&self) -> Option<&Meta> {
        self.meta.as_ref()
    }
    pub fn set_claims(mut self, claims: Vec<DcqlClaim>) -> Self {
        self.claims = Some(claims);
        self
    }
    pub fn add_claim(mut self, claim: DcqlClaim) -> Self {
        if self.claims.is_none() {
            self.claims = Some(vec![claim]);
        } else {
            let mut claims = self.claims.take().expect("claims missing");
            claims.push(claim);
            self.claims = Some(claims);
        }
        self
    }

    pub fn claims(&self) -> Option<&Vec<DcqlClaim>> {
        self.claims.as_ref()
    }

    pub fn set_claim_sets(mut self, sets: Vec<Vec<String>>) -> Self {
        self.claim_sets = Some(sets);
        self
    }
    pub fn add_claim_set(mut self, claim_set: Vec<String>) -> Self {
        if self.claim_sets.is_none() {
            self.claim_sets = Some(vec![claim_set]);
        } else {
            let mut claim_sets = self.claim_sets.take().expect("claim_sets missing");
            claim_sets.push(claim_set);
            self.claim_sets = Some(claim_sets);
        }
        self
    }
    pub fn claim_sets(&self) -> Option<&Vec<Vec<String>>> {
        self.claim_sets.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DcqlCredentialSet {
    options: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<bool>, // default true
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
}

impl DcqlCredentialSet {
    pub fn new(options: Vec<Vec<String>>) -> Self {
        Self {
            options,
            required: None,
            purpose: None,
        }
    }
    pub fn add_option(mut self, option: Vec<String>) -> Self {
        self.options.push(option);
        self
    }
    pub fn options(&self) -> &Vec<Vec<String>> {
        &self.options
    }
    pub fn set_required(mut self, required: bool) -> Self {
        self.required = Some(required);
        self
    }
    pub fn required(&self) -> Option<&bool> {
        self.required.as_ref()
    }
    pub fn set_purpose(mut self, purpose: &str) -> Self {
        self.purpose = Some(purpose.to_string());
        self
    }
    pub fn purpose(&self) -> Option<&String> {
        self.purpose.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Meta {
    #[serde(skip_serializing_if = "Option::is_none")]
    vct_values: Option<Vec<String>>,
}

impl Meta {
    pub fn new(vct_values: Option<Vec<String>>) -> Self {
        Self { vct_values }
    }
    pub fn get_vct_values(&self) -> Option<&Vec<String>> {
        self.vct_values.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DcqlClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<ID>, // REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Vec<PathValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<Vec<ValueType>>,
}

impl DcqlClaim {
    pub fn new() -> Self {
        Self {
            id: None,
            path: None,
            namespace: None,
            claim_name: None,
            values: None,
        }
    }
    pub fn set_id(mut self, id: ID) -> Self {
        self.id = Some(id);
        self
    }

    pub fn id(&self) -> Option<&ID> {
        self.id.as_ref()
    }

    pub fn set_path(mut self, path: Vec<PathValue>) -> Self {
        self.path = Some(path);
        self
    }
    pub fn path(&self) -> Option<&Vec<PathValue>> {
        self.path.as_ref()
    }
    pub fn set_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }
    pub fn namespace(&self) -> Option<&String> {
        self.namespace.as_ref()
    }
    pub fn set_claim_name(mut self, claim_name: &str) -> Self {
        self.claim_name = Some(claim_name.to_string());
        self
    }
    pub fn claim_name(&self) -> Option<&String> {
        self.claim_name.as_ref()
    }
    pub fn set_values(mut self, values: Vec<ValueType>) -> Self {
        self.values = Some(values);
        self
    }
    pub fn values(&self) -> Option<&Vec<ValueType>> {
        self.values.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PathValue {
    String(String),
    Usize(usize),
    Null,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ValueType {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[cfg(test)]
mod test {
    use crate::core::dcql::ID;
    use rstest::rstest;
    #[rstest]
    #[case("\"stub_id\"")]
    #[case("\"stub-id\"")]
    #[case("\"stub0id\"")]
    #[case("\"stub1ID\"")]
    fn test_id_serialize_deserialize(#[case] json: &str) {
        let id = serde_json::from_str::<ID>(json).unwrap();
        println!("{:#?}", id);
        let parsed = serde_json::to_string(&id).unwrap();
        assert_eq!(json, parsed);
    }
    #[rstest]
    #[case("stub id")]
    #[case("stub?id")]
    #[case("stub@id9")]
    #[case("")]
    #[should_panic]
    fn test_id_validation(#[case] wrong_id: &str) {
        let id = ID::new(wrong_id.to_string()).unwrap();
        println!("{:#?}", id);
    }
}

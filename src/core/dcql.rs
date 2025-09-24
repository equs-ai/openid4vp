use crate::core::credential_format::ClaimFormatDesignation;
use crate::core::object::TypedParameter;
use crate::utils::{from_string_or_value, NonEmptyVec};
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DCQL {
    credentials: NonEmptyVec<DcqlCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_sets: Option<NonEmptyVec<DcqlCredentialSet>>,
}

impl DCQL {
    pub fn new(credentials: NonEmptyVec<DcqlCredential>) -> Self {
        Self {
            credentials,
            credential_sets: None,
        }
    }
    pub fn add_credential(mut self, credential: DcqlCredential) -> Self {
        self.credentials.push(credential);
        self
    }

    pub fn add_credential_set(mut self, credential_set: DcqlCredentialSet) -> Self {
        if let Some(mut sets) = self.credential_sets {
            sets.push(credential_set);
            self.credential_sets = Some(sets);
        } else {
            self.credential_sets = Some(NonEmptyVec::new(credential_set));
        }
        self
    }

    pub fn credential_sets(&self) -> Option<&NonEmptyVec<DcqlCredentialSet>> {
        self.credential_sets.as_ref()
    }
    pub fn credentials(&self) -> &NonEmptyVec<DcqlCredential> {
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

impl TryFrom<DCQL> for Json {
    type Error = serde_json::Error;
    fn try_from(value: DCQL) -> Result<Self, Self::Error> {
        serde_json::to_value(value)
    }
}

impl TypedParameter for DCQL {
    const KEY: &'static str = "dcql_query";
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DcqlCredential {
    id: ID,
    format: ClaimFormatDesignation,
    meta: DcqlMeta,
    //Support will be added for multiple in the context of
    #[serde(skip_serializing_if = "Option::is_none")]
    multiple: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<NonEmptyVec<DcqlClaim>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_sets: Option<NonEmptyVec<NonEmptyVec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    require_cryptographic_holder_binding: Option<bool>,
}

impl DcqlCredential {
    pub fn new(id: ID, format: ClaimFormatDesignation, meta: DcqlMeta) -> Self {
        Self {
            id,
            format,
            meta,
            multiple: None,
            claims: None,
            claim_sets: None,
            require_cryptographic_holder_binding: None,
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

    pub fn set_meta(mut self, meta: DcqlMeta) -> Self {
        self.meta = meta;
        self
    }
    pub fn meta(&self) -> &DcqlMeta {
        &self.meta
    }

    pub fn set_multiple(mut self, multiple: bool) -> Self {
        self.multiple = Some(multiple);
        self
    }

    pub fn multiple(&self) -> Option<bool> {
        self.multiple
    }

    pub fn set_require_cryptographic_holder_binding(
        mut self,
        require_cryptographic_holder_binding: bool,
    ) -> Self {
        self.require_cryptographic_holder_binding = Some(require_cryptographic_holder_binding);
        self
    }
    pub fn require_cryptographic_holder_binding(&self) -> Option<bool> {
        self.require_cryptographic_holder_binding
    }
    pub fn set_claims(mut self, claims: NonEmptyVec<DcqlClaim>) -> Self {
        self.claims = Some(claims);
        self
    }
    pub fn add_claim(mut self, claim: DcqlClaim) -> Self {
        if let Some(mut claims) = self.claims {
            claims.push(claim);
            self.claims = Some(claims);
        } else {
            self.claims = Some(NonEmptyVec::new(claim));
        }
        self
    }

    pub fn claims(&self) -> Option<&NonEmptyVec<DcqlClaim>> {
        self.claims.as_ref()
    }

    pub fn set_claim_sets(mut self, sets: NonEmptyVec<NonEmptyVec<String>>) -> Self {
        self.claim_sets = Some(sets);
        self
    }
    pub fn add_claim_set(mut self, claim_set: NonEmptyVec<String>) -> Self {
        if let Some(mut sets) = self.claim_sets {
            sets.push(claim_set);
            self.claim_sets = Some(sets);
        } else {
            self.claim_sets = Some(NonEmptyVec::new(claim_set));
        }
        self
    }
    pub fn claim_sets(&self) -> Option<&NonEmptyVec<NonEmptyVec<String>>> {
        self.claim_sets.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DcqlCredentialSet {
    options: NonEmptyVec<NonEmptyVec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<bool>, // default true
}

impl DcqlCredentialSet {
    pub fn new(options: NonEmptyVec<NonEmptyVec<String>>) -> Self {
        Self {
            options,
            required: None,
        }
    }
    pub fn add_option(mut self, option: NonEmptyVec<String>) -> Self {
        self.options.push(option);
        self
    }
    pub fn options(&self) -> &NonEmptyVec<NonEmptyVec<String>> {
        &self.options
    }
    pub fn set_required(mut self, required: bool) -> Self {
        self.required = Some(required);
        self
    }
    pub fn required(&self) -> Option<&bool> {
        self.required.as_ref()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DcqlMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    vct_values: Option<NonEmptyVec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_values: Option<NonEmptyVec<NonEmptyVec<String>>>,
}

impl DcqlMeta {
    pub fn new() -> Self {
        Self {
            vct_values: None,
            type_values: None,
        }
    }
    pub fn vct_values(&self) -> Option<&NonEmptyVec<String>> {
        self.vct_values.as_ref()
    }
    pub fn set_vct_values(mut self, values: NonEmptyVec<String>) -> Self {
        self.vct_values = Some(values);
        self
    }

    pub fn type_values(&self) -> Option<&NonEmptyVec<NonEmptyVec<String>>> {
        self.type_values.as_ref()
    }
    pub fn set_type_values(mut self, values: NonEmptyVec<NonEmptyVec<String>>) -> Self {
        self.type_values = Some(values);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DcqlClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<ID>, // REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise
    path: NonEmptyVec<PathValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<NonEmptyVec<ValueType>>,
}

impl DcqlClaim {
    pub fn new(path: NonEmptyVec<PathValue>) -> Self {
        Self {
            id: None,
            path,
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

    pub fn set_path(mut self, path: NonEmptyVec<PathValue>) -> Self {
        self.path = path;
        self
    }
    pub fn path(&self) -> &NonEmptyVec<PathValue> {
        &self.path
    }
    pub fn set_values(mut self, values: NonEmptyVec<ValueType>) -> Self {
        self.values = Some(values);
        self
    }
    pub fn values(&self) -> Option<&NonEmptyVec<ValueType>> {
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
    Integer(u64),
    Boolean(bool),
}

#[cfg(test)]
mod test {
    use crate::core::dcql::{
        DcqlClaim, DcqlCredential, DcqlCredentialSet, DcqlMeta, PathValue, DCQL, ID,
    };
    use crate::utils::NonEmptyVec;
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

    #[test]
    fn test_credential_sets_adding() {
        let dcql = get_base_dcql();
        let dcql = dcql.add_credential_set(DcqlCredentialSet::new(NonEmptyVec::new(
            NonEmptyVec::new("1".to_string()),
        )));
        assert_eq!(dcql.to_owned().credential_sets().unwrap().len(), 1);
        let dcql = dcql.add_credential_set(DcqlCredentialSet::new(NonEmptyVec::new(
            NonEmptyVec::new("1".to_string()),
        )));
        assert_eq!(dcql.credential_sets().unwrap().len(), 2);
    }

    #[test]
    fn test_credential_adding() {
        let dcql = get_base_dcql();
        assert_eq!(dcql.credentials().len(), 1);
        let dcql = dcql.add_credential(DcqlCredential::new(
            ID::new(String::from("stub_id2")).unwrap(),
            crate::core::credential_format::ClaimFormatDesignation::SdJwtVc,
            DcqlMeta::new().set_vct_values(NonEmptyVec::new("some_vct_type".to_string())),
        ));
        assert_eq!(dcql.credentials().len(), 2);
    }

    #[test]
    fn test_claim_adding() {
        let credential = get_base_credential();
        let credential = credential.add_claim(DcqlClaim::new(NonEmptyVec::new(PathValue::Null)));
        assert_eq!(credential.to_owned().claims().unwrap().len(), 1);
        let credential = credential.add_claim(DcqlClaim::new(NonEmptyVec::new(PathValue::Null)));
        assert_eq!(credential.claims().unwrap().len(), 2);
    }

    #[test]
    fn test_claim_set_adding() {
        let credential = get_base_credential();
        let credential = credential.add_claim_set(NonEmptyVec::new("1".to_string()));
        assert_eq!(credential.to_owned().claim_sets().unwrap().len(), 1);
        let credential = credential.add_claim_set(NonEmptyVec::new("2".to_string()));
        assert_eq!(credential.claim_sets().unwrap().len(), 2);
    }

    #[test]
    fn test_credential_set_option_adding() {
        let set = DcqlCredentialSet::new(NonEmptyVec::new(NonEmptyVec::new("1".to_string())));
        assert_eq!(set.options().len(), 1);
        let set = set.add_option(NonEmptyVec::new("1".to_string()));
        assert_eq!(set.options().len(), 2);
    }
    fn get_base_dcql() -> DCQL {
        DCQL::new(NonEmptyVec::new(get_base_credential()))
    }

    fn get_base_credential() -> DcqlCredential {
        DcqlCredential::new(
            ID::new(String::from("stub_id")).unwrap(),
            crate::core::credential_format::ClaimFormatDesignation::SdJwtVc,
            DcqlMeta::new().set_type_values(NonEmptyVec::new(NonEmptyVec::new(
                "som_type_vale".to_string(),
            ))),
        )
    }
}

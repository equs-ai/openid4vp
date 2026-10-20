use crate::core::credential_format::ClaimFormatDesignation;
use crate::core::object::TypedParameter;
use crate::utils::{from_string_or_value, NonEmptyVec};
use anyhow::{ensure, Error};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
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
        ID::new(parsed)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_authorities: Option<NonEmptyVec<TrustedAuthority>>,
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
            trusted_authorities: None,
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

    /// Issuers the Verifier expects, as a hint to the Wallet (OpenID4VP 1.0 §6.1.1).
    pub fn set_trusted_authorities(
        mut self,
        trusted_authorities: NonEmptyVec<TrustedAuthority>,
    ) -> Self {
        self.trusted_authorities = Some(trusted_authorities);
        self
    }
    pub fn trusted_authorities(&self) -> Option<&NonEmptyVec<TrustedAuthority>> {
        self.trusted_authorities.as_ref()
    }
}

/// An entry of a Trusted Authorities Query (OpenID4VP 1.0 §6.1.1): a trust framework `type` and the
/// values it is matched against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawTrustedAuthority", into = "RawTrustedAuthority")]
pub enum TrustedAuthority {
    /// `aki` (§6.1.1.1): Key Identifiers of an X.509 AuthorityKeyIdentifier.
    Aki(NonEmptyVec<KeyIdentifier>),
    /// `etsi_tl` (§6.1.1.2): identifiers of ETSI TS 119 612 Trusted Lists.
    EtsiTl(NonEmptyVec<String>),
    /// `openid_federation` (§6.1.1.3): OpenID Federation Entity Identifiers.
    OpenidFederation(NonEmptyVec<String>),
    /// Any other type, kept as received.
    Other {
        r#type: String,
        values: NonEmptyVec<String>,
    },
}

impl TrustedAuthority {
    pub const AKI: &'static str = "aki";
    pub const ETSI_TL: &'static str = "etsi_tl";
    pub const OPENID_FEDERATION: &'static str = "openid_federation";
}

#[derive(Serialize, Deserialize)]
struct RawTrustedAuthority {
    r#type: String,
    values: NonEmptyVec<String>,
}

impl TryFrom<RawTrustedAuthority> for TrustedAuthority {
    type Error = Error;

    fn try_from(raw: RawTrustedAuthority) -> Result<Self, Self::Error> {
        Ok(match raw.r#type.as_str() {
            Self::AKI => Self::Aki(NonEmptyVec::try_from(
                raw.values
                    .into_iter()
                    .map(KeyIdentifier::from_base64url)
                    .collect::<Result<Vec<_>, _>>()?,
            )?),
            Self::ETSI_TL => Self::EtsiTl(raw.values),
            Self::OPENID_FEDERATION => Self::OpenidFederation(raw.values),
            _ => Self::Other {
                r#type: raw.r#type,
                values: raw.values,
            },
        })
    }
}

impl From<TrustedAuthority> for RawTrustedAuthority {
    fn from(authority: TrustedAuthority) -> Self {
        match authority {
            TrustedAuthority::Aki(values) => Self {
                r#type: TrustedAuthority::AKI.to_string(),
                values: values.map(|value| value.encoded),
            },
            TrustedAuthority::EtsiTl(values) => Self {
                r#type: TrustedAuthority::ETSI_TL.to_string(),
                values,
            },
            TrustedAuthority::OpenidFederation(values) => Self {
                r#type: TrustedAuthority::OPENID_FEDERATION.to_string(),
                values,
            },
            TrustedAuthority::Other { r#type, values } => Self { r#type, values },
        }
    }
}

/// An X.509 Key Identifier, kept as the base64url text it was given and as its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyIdentifier {
    encoded: String,
    bytes: Vec<u8>,
}

impl KeyIdentifier {
    /// A Key Identifier from its base64url encoding, which is kept as given.
    pub fn from_base64url(encoded: String) -> Result<Self, Error> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('='))?;
        ensure!(!bytes.is_empty(), "a Key Identifier cannot be empty");
        Ok(Self { encoded, bytes })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ensure!(!bytes.is_empty(), "a Key Identifier cannot be empty");
        Ok(Self {
            encoded: BASE64_URL_SAFE_NO_PAD.encode(bytes),
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_base64url(&self) -> &str {
        &self.encoded
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct DcqlMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    vct_values: Option<NonEmptyVec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_values: Option<NonEmptyVec<NonEmptyVec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doctype_value: Option<String>,
}

impl DcqlMeta {
    pub fn new() -> Self {
        Self {
            vct_values: None,
            type_values: None,
            doctype_value: None,
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

    pub fn doctype_value(&self) -> Option<&String> {
        self.doctype_value.as_ref()
    }
    pub fn set_doctype_value(mut self, value: String) -> Self {
        self.doctype_value = Some(value);
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

    #[test]
    fn test_meta_for_doctype_value() {
        let meta = DcqlMeta::new();
        assert_eq!(meta.doctype_value(), None);
        let meta = meta.set_doctype_value("org.iso.18013.5.1.mDL".to_string());
        assert_eq!(
            meta.doctype_value().unwrap(),
            &"org.iso.18013.5.1.mDL".to_string()
        );
    }

    #[test]
    fn test_meta_for_vct_values() {
        let meta = DcqlMeta::new();
        assert_eq!(meta.vct_values(), None);
        let meta = meta.set_vct_values(NonEmptyVec::new("credential_type".to_string()));
        assert_eq!(
            meta.vct_values().unwrap().first().unwrap(),
            &"credential_type".to_string()
        );
    }

    #[test]
    fn test_meta_for_type_values() {
        let meta = DcqlMeta::new();
        assert_eq!(meta.type_values(), None);
        let meta = meta.set_type_values(NonEmptyVec::new(NonEmptyVec::new(
            "credential_types".to_string(),
        )));
        assert_eq!(
            meta.type_values()
                .unwrap()
                .first()
                .unwrap()
                .first()
                .unwrap(),
            &"credential_types".to_string()
        );
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

    mod trusted_authorities {
        use super::super::*;
        use serde_json::json;

        fn credential_with(trusted_authorities: Json) -> Result<DcqlCredential, serde_json::Error> {
            serde_json::from_value(json!({
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "trusted_authorities": trusted_authorities
            }))
        }

        #[test]
        fn every_type_round_trips_unchanged() {
            let authorities = json!([
                { "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y", "AQID"] },
                { "type": "etsi_tl", "values": ["https://lotl.example.com/tl.xml"] },
                { "type": "openid_federation", "values": ["https://trust-anchor.example.com"] },
                { "type": "x_custom", "values": ["anything"] }
            ]);

            let credential = credential_with(authorities.clone()).unwrap();
            let serialized = serde_json::to_value(&credential).unwrap();

            assert_eq!(serialized["trusted_authorities"], authorities);
            let parsed = credential.trusted_authorities().unwrap();
            let TrustedAuthority::Aki(akis) = &parsed[0] else {
                panic!("expected aki, got {:?}", parsed[0]);
            };
            assert_eq!(akis[1].as_bytes(), [1, 2, 3]);
            assert!(matches!(parsed[1], TrustedAuthority::EtsiTl(_)));
            assert!(matches!(parsed[2], TrustedAuthority::OpenidFederation(_)));
            assert!(matches!(
                &parsed[3],
                TrustedAuthority::Other { r#type, .. } if r#type == "x_custom"
            ));
        }

        #[test]
        fn absent_trusted_authorities_are_not_serialized() {
            let credential: DcqlCredential = serde_json::from_value(json!({
                "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] }
            }))
            .unwrap();

            assert!(credential.trusted_authorities().is_none());
            let serialized = serde_json::to_value(&credential).unwrap();
            assert!(serialized.get("trusted_authorities").is_none());
        }

        #[rstest::rstest]
        #[case::empty_list(json!([]))]
        #[case::empty_values(json!([{ "type": "aki", "values": [] }]))]
        #[case::not_base64url(json!([{ "type": "aki", "values": ["not base64!"] }]))]
        #[case::empty_key_identifier(json!([{ "type": "aki", "values": [""] }]))]
        #[case::missing_type(json!([{ "values": ["AQID"] }]))]
        fn malformed_trusted_authorities_are_refused(#[case] authorities: Json) {
            assert!(credential_with(authorities).is_err());
        }

        #[test]
        fn a_padded_key_identifier_is_accepted_and_kept_as_given() {
            let credential =
                credential_with(json!([{ "type": "aki", "values": ["AQI="] }])).unwrap();

            let serialized = serde_json::to_value(&credential).unwrap();
            assert_eq!(
                serialized["trusted_authorities"],
                json!([{ "type": "aki", "values": ["AQI="] }])
            );
            let TrustedAuthority::Aki(akis) = &credential.trusted_authorities().unwrap()[0] else {
                panic!("expected aki");
            };
            assert_eq!(akis[0].as_bytes(), [1, 2]);
        }

        #[test]
        fn key_identifier_from_bytes_is_base64url_without_padding() {
            let key_identifier = KeyIdentifier::from_bytes(&[0xfb, 0xff]).unwrap();

            assert_eq!(key_identifier.as_base64url(), "-_8");
            assert_eq!(key_identifier.as_bytes(), [0xfb, 0xff]);
        }

        #[test]
        fn builder_sets_trusted_authorities() {
            let aki = KeyIdentifier::from_bytes(&[1, 2, 3]).unwrap();
            let credential = DcqlCredential::new(
                ID::new("pid".to_string()).unwrap(),
                serde_json::from_value(json!("dc+sd-jwt")).unwrap(),
                serde_json::from_value(json!({ "vct_values": ["urn:eudi:pid:1"] })).unwrap(),
            )
            .set_trusted_authorities(NonEmptyVec::new(TrustedAuthority::Aki(NonEmptyVec::new(
                aki,
            ))));

            assert_eq!(
                serde_json::to_value(&credential).unwrap()["trusted_authorities"],
                json!([{ "type": "aki", "values": ["AQID"] }])
            );
        }
    }
}

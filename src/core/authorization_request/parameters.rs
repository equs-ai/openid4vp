use super::AuthorizationRequestObject;
use crate::core::{
    metadata::parameters::verifier::{
        AuthorizationEncryptedResponseAlg, AuthorizationEncryptedResponseEnc,
        AuthorizationSignedResponseAlg, JWKs, VpFormats,
    },
    object::{TypedParameter, UntypedObject},
};
use crate::utils::from_string_or_value;
use anyhow::{anyhow, bail, Error, Ok};
use base64::engine::general_purpose;
use base64::Engine;
use p256::elliptic_curve::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::{fmt, ops::Deref};
use url::Url;

pub const DID: &str = "did";
/// Deprecated, use `https` instead.
pub const ENTITY_ID: &str = "entity_id";
pub const HTTPS: &str = "https";
pub const PREREGISTERED: &str = "pre-registered";
pub const REDIRECT_URI: &str = "redirect_uri";
pub const VERIFIER_ATTESTATION: &str = "verifier_attestation";
pub const WEB_ORIGIN: &str = "web-origin";
pub const X509_SAN_DNS: &str = "x509_san_dns";
pub const X509_SAN_URI: &str = "x509_san_uri";

#[derive(Debug, Clone)]
pub struct ClientId {
    id: String,
    scheme: ClientIdScheme,
}

impl ClientId {
    pub fn new(client_id: String) -> Result<Self, Error> {
        if client_id.is_empty() {
            return Err(anyhow!("Client ID cannot be empty."));
        }
        let parts = client_id.splitn(2, ':').collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 2 {
            return Err(anyhow!("Error while parsing client id: {}", client_id));
        }
        if parts.len() == 1 {
            return Ok(Self {
                id: parts[0].to_string(),
                scheme: ClientIdScheme::PreRegistered,
            });
        }

        let scheme = ClientIdScheme::try_from(parts[0].to_string())?;
        let id = match scheme {
            ClientIdScheme::Did | ClientIdScheme::Https => client_id.clone(),
            ClientIdScheme::PreRegistered
            | ClientIdScheme::RedirectUri
            | ClientIdScheme::X509SanDns
            | ClientIdScheme::EntityId
            | ClientIdScheme::WebOrigin
            | ClientIdScheme::VerifierAttestation
            | ClientIdScheme::X509SanUri => parts[1].to_string(),
        };
        Ok(Self { id, scheme })
    }
    pub fn get_scheme(&self) -> &ClientIdScheme {
        &self.scheme
    }

    pub fn get_id(&self) -> String {
        self.id.to_owned()
    }

    pub fn get_full_id(&self) -> String {
        let id = match self.scheme {
            ClientIdScheme::Did | ClientIdScheme::EntityId => self.get_id().to_owned(),
            ClientIdScheme::Https
            | ClientIdScheme::PreRegistered
            | ClientIdScheme::RedirectUri
            | ClientIdScheme::VerifierAttestation
            | ClientIdScheme::WebOrigin
            | ClientIdScheme::X509SanDns
            | ClientIdScheme::X509SanUri => {
                format!("{}:{}", self.get_scheme().to_string(), self.get_id())
            }
        };
        id
    }
}

impl TypedParameter for ClientId {
    const KEY: &'static str = "client_id";
}

impl TryFrom<Json> for ClientId {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Self::new(serde_json::from_value(value)?)
    }
}

impl From<ClientId> for Json {
    fn from(value: ClientId) -> Self {
        Json::String(value.get_full_id().to_owned())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientIdScheme {
    Did,
    EntityId,
    Https,
    PreRegistered,
    RedirectUri,
    VerifierAttestation,
    WebOrigin,
    X509SanDns,
    X509SanUri,
}

impl TryFrom<String> for ClientIdScheme {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            DID => Ok(ClientIdScheme::Did),
            ENTITY_ID => Ok(ClientIdScheme::EntityId),
            HTTPS => Ok(ClientIdScheme::Https),
            PREREGISTERED => Ok(ClientIdScheme::PreRegistered),
            REDIRECT_URI => Ok(ClientIdScheme::RedirectUri),
            VERIFIER_ATTESTATION => Ok(ClientIdScheme::VerifierAttestation),
            WEB_ORIGIN => Ok(ClientIdScheme::WebOrigin),
            X509_SAN_DNS => Ok(ClientIdScheme::X509SanDns),
            X509_SAN_URI => Ok(ClientIdScheme::X509SanUri),
            _ => Err(anyhow!(
                "Given client id scheme is not supported: {}",
                value
            )),
        }
    }
}
impl From<ClientIdScheme> for String {
    fn from(value: ClientIdScheme) -> Self {
        match value {
            ClientIdScheme::Did => DID.to_string(),
            ClientIdScheme::EntityId => ENTITY_ID.to_string(),
            ClientIdScheme::Https => HTTPS.to_string(),
            ClientIdScheme::PreRegistered => PREREGISTERED.to_string(),
            ClientIdScheme::RedirectUri => REDIRECT_URI.to_string(),
            ClientIdScheme::VerifierAttestation => VERIFIER_ATTESTATION.to_string(),
            ClientIdScheme::WebOrigin => WEB_ORIGIN.to_string(),
            ClientIdScheme::X509SanDns => X509_SAN_DNS.to_string(),
            ClientIdScheme::X509SanUri => X509_SAN_URI.to_string(),
        }
    }
}

impl fmt::Display for ClientIdScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(self.to_owned()))
    }
}

impl TryFrom<Json> for ClientIdScheme {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
            .map(String::try_into)?
            .map_err(Error::from)
    }
}

impl From<ClientIdScheme> for Json {
    fn from(value: ClientIdScheme) -> Self {
        Json::String(String::from(value))
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionData(pub Vec<String>);

impl TryFrom<Json> for TransactionData {
    type Error = Error;
    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<TransactionData> for Json {
    fn from(value: TransactionData) -> Self {
        Json::Array(value.0.into_iter().map(Json::String).collect())
    }
}
impl TypedParameter for TransactionData {
    const KEY: &'static str = "transaction_data";
}
pub struct TransactionDataItem {
    pub type_: String,
    pub credential_ids: Vec<String>,
    pub transaction_data_hashes_alg: Option<Vec<String>>,
}

/// `client_metadata` field in the Authorization Request.
///
/// client_metadata: OPTIONAL. A JSON object containing the Verifier metadata values.
/// It MUST be UTF-8 encoded. The following metadata parameters MAY be used:
///
/// jwks: OPTIONAL. A JWKS as defined in [RFC7591]. It MAY contain one or more public keys, such as those used by the Wallet as an input to a key agreement that may be used for encryption of the Authorization Response (see Section 7.3), or where the Wallet will require the public key of the Verifier to generate the Verifiable Presentation. This allows the Verifier to pass ephemeral keys specific to this Authorization Request. Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests.
/// vp_formats: REQUIRED when not available to the Wallet via another mechanism. As defined in Section 10.1.
/// authorization_signed_response_alg: OPTIONAL. As defined in [JARM].
/// authorization_encrypted_response_alg: OPTIONAL. As defined in [JARM].
/// authorization_encrypted_response_enc: OPTIONAL. As defined in [JARM].
/// Authoritative data the Wallet is able to obtain about the Client from other sources,
/// for example those from an OpenID Federation Entity Statement, take precedence over the
/// values passed in client_metadata. Other metadata parameters MUST be ignored unless a
/// profile of this specification explicitly defines them as usable in the client_metadata parameter.
///
///
/// See reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.4
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata(pub UntypedObject);

impl TypedParameter for ClientMetadata {
    const KEY: &'static str = "client_metadata";
}

impl From<ClientMetadata> for Json {
    fn from(cm: ClientMetadata) -> Self {
        cm.0 .0.into()
    }
}

impl TryFrom<Json> for ClientMetadata {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(from_string_or_value(&value).map(ClientMetadata)?)
    }
}

impl ClientMetadata {
    /// Resolves the client metadata from the Authorization Request Object.
    ///
    /// If the client metadata is not passed correctly then this function will return an error.
    /// or if not passed, then it returns an empty metadata.
    pub async fn resolve(request: &AuthorizationRequestObject) -> Result<Self, Error> {
        if let Some(metadata) = request.get() {
            return metadata;
        }

        tracing::warn!("the client metadata was not passed by reference or value");
        Ok(ClientMetadata(UntypedObject::default()))
    }

    /// OPTIONAL. A JWKS as defined in
    /// [RFC7591](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#RFC7591).
    ///
    /// It MAY contain one or more public keys, such as those used by the Wallet as an input to a
    /// key agreement that may be used for encryption of the Authorization Response
    /// (see [Section 7.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#jarm)),
    /// or where the Wallet will require the public key of the Verifier to generate the Verifiable Presentation.
    ///
    /// This allows the Verifier to pass ephemeral keys specific to this Authorization Request.
    /// Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests.
    ///
    ///
    /// See reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.1
    ///
    /// The jwks_uri or jwks metadata parameters can be used by clients to register their public encryption keys.
    ///
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-4
    ///
    pub fn jwks(&self) -> Option<Result<JWKs, Error>> {
        self.0.get()
    }

    /// Return the `VpFormats` from the `client_metadata` field.
    ///
    /// vp_formats: REQUIRED when not available to the Wallet via another mechanism.
    ///
    /// As defined in [Section 10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#client_metadata_parameters).
    ///
    /// See reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.2
    pub fn vp_formats(&self) -> Result<VpFormats, Error> {
        self.0.get().ok_or(anyhow!("missing vp_formats"))?
    }

    /// OPTIONAL. As defined in [JARM](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#JARM).
    ///
    /// JARM -> JWT Secured Authorization Response Mode for OAuth 2.0
    ///
    /// The JWS [RFC7515](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7515)
    /// `alg` algorithm REQUIRED for signing authorization responses.
    ///
    /// If this is specified, the response will be signed using JWS and the configured algorithm.
    ///
    /// If unspecified, the default algorithm to use for signing authorization responses is RS256.
    ///
    /// The algorithm none is not allowed.
    ///
    ///  A list of defined ["alg" values](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1)
    /// for this use can be found in the IANA "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA](https://www.rfc-editor.org/rfc/rfc7515.html#ref-JWA); the initial contents of this registry are the values
    /// defined in Section 3.1 of [JWA](https://www.rfc-editor.org/rfc/rfc7515.html#ref-JWA).
    ///
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.3
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-3.2.1
    /// See: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
    ///
    pub fn authorization_signed_response_alg(
        &self,
    ) -> Result<AuthorizationSignedResponseAlg, Error> {
        self.0.get().unwrap_or(Ok(AuthorizationSignedResponseAlg(
            ssi::crypto::Algorithm::RS256,
        )))
    }

    /// OPTIONAL. As defined in [JARM](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#JARM).
    ///
    /// JARM -> JWT Secured Authorization Response Mode for OAuth 2.0
    ///
    /// The JWE [RFC7516](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7516)
    /// `alg` algorithm REQUIRED for encrypting authorization responses.
    ///
    /// If both signing and encryption are requested, the response will be signed then encrypted,
    /// with the result being a Nested JWT, as defined in JWT
    /// [RFC7519](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7519).
    ///
    /// The default, if omitted, is that no encryption is performed.
    ///
    ///
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.4
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-3.4.1
    ///
    pub fn authorization_encrypted_response_alg(
        &self,
    ) -> Option<Result<AuthorizationEncryptedResponseAlg, Error>> {
        self.0.get()
    }

    /// OPTIONAL. As defined in [JARM](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#JARM).
    ///
    /// JARM -> JWT Secured Authorization Response Mode for OAuth 2.0
    ///
    /// The JWE [RFC7516](https://openid.net/specs/oauth-v2-jarm-final.html#RFC7516) `enc` algorithm
    /// REQUIRED for encrypting authorization responses.
    ///
    /// If `authorization_encrypted_response_alg` is specified, the default for this value is `A128CBC-HS256`.
    ///
    /// When `authorization_encrypted_response_enc` is included, authorization_encrypted_response_alg MUST also be provided.
    ///
    /// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-4.2.2.5
    /// See: https://openid.net/specs/oauth-v2-jarm-final.html#section-3-3.6.1
    ///
    pub fn authorization_encrypted_response_enc(
        &self,
    ) -> Option<Result<AuthorizationEncryptedResponseEnc, Error>> {
        match self.0.get() {
            Some(enc) => Some(enc),
            None => self
                .authorization_encrypted_response_alg()
                .map(|_| Ok(AuthorizationEncryptedResponseEnc("A128CBC-HS256".into()))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nonce(String);

impl From<String> for Nonce {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<Nonce> for String {
    fn from(value: Nonce) -> Self {
        value.0
    }
}

impl From<&str> for Nonce {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Deref for Nonce {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Nonce {
    /// Crate a new `Nonce` with a random value of the given length.
    pub fn random(rng: &mut impl rand::Rng, length: usize) -> Self {
        use rand::distributions::{Alphanumeric, DistString};

        Self(Alphanumeric.sample_string(rng, length))
    }
}

impl TypedParameter for Nonce {
    const KEY: &'static str = "nonce";
}

impl TryFrom<Json> for Nonce {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<Nonce> for Json {
    fn from(value: Nonce) -> Self {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletNonce(pub String);
impl WalletNonce {
    /// Crate a new `WalletNonce` with a random value. base-64 encoded.

    pub fn random() -> Self {
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        // Encode as base64url (URL-safe base64 without padding)
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        Self(encoded)
    }
}

impl TypedParameter for WalletNonce {
    const KEY: &'static str = "wallet_nonce";
}

impl TryFrom<Json> for WalletNonce {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<WalletNonce> for Json {
    fn from(value: WalletNonce) -> Self {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone)]
pub struct Audience(pub String);

impl TypedParameter for Audience {
    const KEY: &'static str = "aud";
}

impl TryFrom<Json> for Audience {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<Audience> for Json {
    fn from(value: Audience) -> Json {
        Json::String(value.0)
    }
}

/// `redirect_uri` field in the Authorization Request.
#[derive(Debug, Clone)]
pub struct RedirectUri(pub Url);

impl TypedParameter for RedirectUri {
    const KEY: &'static str = "redirect_uri";
}

impl From<RedirectUri> for Json {
    fn from(cmu: RedirectUri) -> Self {
        cmu.0.to_string().into()
    }
}

impl TryFrom<Json> for RedirectUri {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(RedirectUri)?)
    }
}

/// `response_uri` field in the Authorization Request.
#[derive(Debug, Clone)]
pub struct ResponseUri(pub Url);

impl ResponseUri {
    pub fn new(url: Url) -> Self {
        Self(url)
    }
}

impl TypedParameter for ResponseUri {
    const KEY: &'static str = "response_uri";
}

impl From<ResponseUri> for Json {
    fn from(cmu: ResponseUri) -> Self {
        cmu.0.to_string().into()
    }
}

impl TryFrom<Json> for ResponseUri {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(ResponseUri)?)
    }
}

const DIRECT_POST: &str = "direct_post";
const DIRECT_POST_JWT: &str = "direct_post.jwt";
const DC_API: &str = "dc_api";
const DC_API_JWT: &str = "dc_api.jwt";

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(into = "String", from = "String")]
pub enum ResponseMode {
    /// The `direct_post` response mode as defined in OID4VP.
    DirectPost,
    /// The `direct_post.jwt` response mode as defined in OID4VP.
    DirectPostJwt,
    /// The `dc_api` response mode as defined in OID4VP.
    #[default]
    DCAPI,
    /// The `dc_api.jwt` response mode as defined in OID4VP.
    DCAPIJwt,
    /// A ResponseMode that is unsupported by this library.
    Unsupported(String),
}

impl TypedParameter for ResponseMode {
    const KEY: &'static str = "response_mode";
}

impl From<String> for ResponseMode {
    fn from(s: String) -> Self {
        match s.as_str() {
            DIRECT_POST => ResponseMode::DirectPost,
            DIRECT_POST_JWT => ResponseMode::DirectPostJwt,
            DC_API => ResponseMode::DCAPI,
            DC_API_JWT => ResponseMode::DCAPIJwt,
            _ => ResponseMode::Unsupported(s),
        }
    }
}

impl From<ResponseMode> for String {
    fn from(s: ResponseMode) -> Self {
        match s {
            ResponseMode::DirectPost => DIRECT_POST.into(),
            ResponseMode::DirectPostJwt => DIRECT_POST_JWT.into(),
            ResponseMode::DCAPI => DC_API.into(),
            ResponseMode::DCAPIJwt => DC_API_JWT.into(),
            ResponseMode::Unsupported(u) => u,
        }
    }
}

impl TryFrom<Json> for ResponseMode {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let s: String = serde_json::from_value(value)?;
        Ok(s.into())
    }
}

impl From<ResponseMode> for Json {
    fn from(rm: ResponseMode) -> Self {
        String::from(rm).into()
    }
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseMode::DirectPost => DIRECT_POST,
            ResponseMode::DirectPostJwt => DIRECT_POST_JWT,
            ResponseMode::DCAPI => DC_API,
            ResponseMode::DCAPIJwt => DC_API_JWT,
            ResponseMode::Unsupported(u) => u,
        }
        .fmt(f)
    }
}

impl ResponseMode {
    pub fn is_jarm(&self) -> Result<bool, Error> {
        match self {
            ResponseMode::DirectPost => Ok(false),
            ResponseMode::DirectPostJwt => Ok(true),
            ResponseMode::DCAPI => Ok(false),
            ResponseMode::DCAPIJwt => Ok(true),
            ResponseMode::Unsupported(rm) => bail!("unsupported response_mode: {rm}"),
        }
    }
}

const VP_TOKEN: &str = "vp_token";
const VP_TOKEN_ID_TOKEN: &str = "vp_token id_token";
const SUBJECT_SIGNED_ID_TOKEN_TYPE: &str = "subject_signed_id_token";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(into = "String", from = "String")]
pub enum ResponseType {
    VpToken,
    VpTokenIdToken,
    Unsupported(String),
}

impl From<ResponseType> for String {
    fn from(rt: ResponseType) -> Self {
        match rt {
            ResponseType::VpToken => VP_TOKEN.into(),
            ResponseType::VpTokenIdToken => VP_TOKEN_ID_TOKEN.into(),
            ResponseType::Unsupported(s) => s,
        }
    }
}

impl From<String> for ResponseType {
    fn from(s: String) -> Self {
        match s.as_str() {
            VP_TOKEN => ResponseType::VpToken,
            VP_TOKEN_ID_TOKEN => ResponseType::VpTokenIdToken,
            _ => ResponseType::Unsupported(s),
        }
    }
}

impl TypedParameter for ResponseType {
    const KEY: &'static str = "response_type";
}

impl TryFrom<Json> for ResponseType {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let s: String = serde_json::from_value(value)?;
        Ok(s.into())
    }
}

impl From<ResponseType> for Json {
    fn from(rt: ResponseType) -> Self {
        Json::String(rt.into())
    }
}

#[derive(Debug, Clone)]
pub struct State(pub String);

impl TypedParameter for State {
    const KEY: &'static str = "state";
}

impl TryFrom<Json> for State {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<State> for Json {
    fn from(value: State) -> Self {
        Json::String(value.0)
    }
}
#[derive(Debug, Clone)]
pub struct PresentationDefinitionUri(pub Url);

impl TypedParameter for PresentationDefinitionUri {
    const KEY: &'static str = "presentation_definition_uri";
}

impl TryFrom<Json> for PresentationDefinitionUri {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value).map(Self)?)
    }
}

impl From<PresentationDefinitionUri> for Json {
    fn from(value: PresentationDefinitionUri) -> Self {
        value.0.to_string().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope(pub String);

impl TypedParameter for Scope {
    const KEY: &'static str = "scope";
}

impl TryFrom<Json> for Scope {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        anyhow::Ok(Self(serde_json::from_value(value)?))
    }
}

impl From<Scope> for Json {
    fn from(value: Scope) -> Self {
        Json::String(value.0)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(into = "String", from = "String")]
pub enum IdTokenType {
    SubjectSigned,
    Unsupported(String),
}

impl From<IdTokenType> for String {
    fn from(idt: IdTokenType) -> Self {
        match idt {
            IdTokenType::SubjectSigned => SUBJECT_SIGNED_ID_TOKEN_TYPE.into(),
            IdTokenType::Unsupported(s) => s,
        }
    }
}

impl From<String> for IdTokenType {
    fn from(s: String) -> Self {
        match s.as_str() {
            SUBJECT_SIGNED_ID_TOKEN_TYPE => IdTokenType::SubjectSigned,
            _ => IdTokenType::Unsupported(s),
        }
    }
}

impl TypedParameter for IdTokenType {
    const KEY: &'static str = "id_token_type";
}

impl TryFrom<Json> for IdTokenType {
    type Error = Error;

    fn try_from(value: Json) -> Result<Self, Self::Error> {
        let s: String = serde_json::from_value(value)?;
        Ok(s.into())
    }
}

impl From<IdTokenType> for Json {
    fn from(idt: IdTokenType) -> Self {
        Json::String(idt.into())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethodForAuth {
    GET,
    POST,
}

impl TryFrom<String> for HttpMethodForAuth {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "get" => Ok(HttpMethodForAuth::GET),
            "post" => Ok(HttpMethodForAuth::POST),
            _ => Err(anyhow::anyhow!(
                "Error parsing http method for Auth".to_string()
            )),
        }
    }
}

impl From<HttpMethodForAuth> for String {
    fn from(value: HttpMethodForAuth) -> String {
        match value {
            HttpMethodForAuth::GET => String::from("get"),
            HttpMethodForAuth::POST => String::from("post"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::core::authorization_request::parameters::{ClientId, ClientIdScheme};
    use crate::core::authorization_request::ResolvedPresentationQuery;
    use crate::core::dcql::DcqlCredential;
    use rstest::rstest;
    use serde_json::json;
    #[rstest]
    #[case(
        "redirect_uri:https://client.example.org/cb",
        "redirect_uri",
        "https://client.example.org/cb"
    )]
    #[case("did:web:someid", "did", "did:web:someid")]
    #[case(
        "x509_san_dns:client.example.org",
        "x509_san_dns",
        "client.example.org"
    )]
    #[case(
        "https://client.example.org/cb",
        "https",
        "https://client.example.org/cb"
    )]
    #[case(
        "verifier_attestation:example-client",
        "verifier_attestation",
        "example-client"
    )]
    fn test_client_id_scheme_parsing_successfully(
        #[case] client_id: String,
        #[case] scheme: String,
        #[case] id: &str,
    ) {
        let client_id = ClientId::new(client_id).unwrap();

        assert_eq!(
            ClientIdScheme::try_from(scheme).unwrap(),
            client_id.get_scheme().to_owned()
        );
        assert_eq!(id, client_id.get_id());
    }

    #[rstest]
    #[case("https//verifier.com")]
    fn client_id_scheme_parsing_successfully_for_preregistered(#[case] id: String) {
        let client_id = ClientId::new(id.clone()).unwrap();
        assert_eq!(
            ClientIdScheme::PreRegistered,
            client_id.get_scheme().to_owned()
        );
    }

    #[rstest]
    #[should_panic(expected = "Given client id scheme is not supported")]
    #[case("some:id/something")]
    #[should_panic(expected = "Client ID cannot be empty.")]
    #[case("")]
    fn client_id_parsing_unsuccessfully(#[case] id: String) {
        ClientId::new(id).unwrap();
    }

    #[rstest]
    #[case("some:id/something")]
    #[should_panic(expected = "Given client id scheme is not supported")]
    fn client_id_parsing_unsuccessfully_unsupported_scheme(#[case] id: String) {
        ClientId::new(id).unwrap();
    }
    #[test]
    fn test() {
        serde_json::from_value::<DcqlCredential>(json!(
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "claims": [
                {
                  "path": [
                    "username"
                  ]
                },
                {
                  "path": [
                    "birthDate"
                  ]
                },
                {
                  "path": [
                    "email",
                    "work"
                  ]
                }
              ]
            }
        ))
        .unwrap();
    }
    #[test]
    fn deserialize_common_presentation() {
        get_json();
    }

    fn get_json() -> ResolvedPresentationQuery {
        serde_json::from_value(json!(
          {
              "presentation_definition": {
              "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                        "input_descriptors": [
                          {
                            "id": "Identity-1",
                            "name": "Identity VC",
                            "purpose": "We want an identity"
                          }
                        ]
          }
        }
        ))
        .unwrap()
    }
}

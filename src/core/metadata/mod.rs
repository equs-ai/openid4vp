use super::credential_format::*;

use std::ops::{Deref, DerefMut};

use self::parameters::wallet::{AuthorizationEndpoint, VpFormatsSupported};
use super::{
    authorization_request::parameters::ResponseType,
    object::{ParsingErrorContext, UntypedObject},
};
use crate::core::authorization_request::parameters::ClientIdScheme;
use crate::core::metadata::parameters::wallet::{
    ClientIdSchemesSupported, IdTokenSigningAlgValuesSupported, IdTokenTypesSupported,
    ScopesSupported,
};
use crate::core::metadata::parameters::SubjectSyntaxTypesSupported;
use anyhow::{Error, Result};
use parameters::wallet::{RequestObjectSigningAlgValuesSupported, ResponseTypesSupported};
use serde::{Deserialize, Serialize};

pub mod parameters;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "UntypedObject", into = "UntypedObject")]
pub struct WalletMetadata(
    UntypedObject,
    AuthorizationEndpoint,
    VpFormatsSupported,
    ResponseTypesSupported,
    ClientIdSchemesSupported,
    RequestObjectSigningAlgValuesSupported,
    ScopesSupported,
    SubjectSyntaxTypesSupported,
    IdTokenTypesSupported,
    IdTokenSigningAlgValuesSupported,
);

impl WalletMetadata {
    pub fn new(
        authorization_endpoint: AuthorizationEndpoint,
        vp_formats_supported: VpFormatsSupported,
        response_types_supported: ResponseTypesSupported,
        other: Option<UntypedObject>,
    ) -> Self {
        Self(
            other.unwrap_or_default(),
            authorization_endpoint,
            vp_formats_supported,
            response_types_supported,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }

    pub fn authorization_endpoint(&self) -> &AuthorizationEndpoint {
        &self.1
    }

    /// Return a reference to the vp formats supported.
    pub fn vp_formats_supported(&self) -> &VpFormatsSupported {
        &self.2
    }

    /// Return a mutable reference to the vp formats supported.
    pub fn vp_formats_supported_mut(&mut self) -> &mut VpFormatsSupported {
        &mut self.2
    }

    /// Return a reference to the supported response types.
    pub fn response_types_supported(&self) -> &ResponseTypesSupported {
        &self.3
    }

    /// Return a reference to the supported client_id schemas.
    pub fn client_id_schema_supported(&self) -> &ClientIdSchemesSupported {
        &self.4
    }

    /// Check that a client-id-schema is supported.
    pub fn is_client_id_schema_supported(&self, client_id_scheme: &ClientIdScheme) -> bool {
        self.client_id_schema_supported().0.contains(client_id_scheme)
    }

    /// Return a reference to the supported response types.
    pub fn subject_syntax_types_supported(&self) -> &SubjectSyntaxTypesSupported {
        &self.7
    }

    /// The static wallet metadata bound to `openid4vp:`:
    /// ```json
    /// {
    ///   "authorization_endpoint": "openid4vp:",
    ///   "response_types_supported": [
    ///     "vp_token"
    ///   ],
    ///   "vp_formats_supported": {
    ///     "jwt_vp_json": {
    ///       "alg_values_supported": ["ES256"]
    ///     },
    ///     "jwt_vc_json": {
    ///       "alg_values_supported": ["ES256"]
    ///     }
    ///   },
    ///   "request_object_signing_alg_values_supported": [
    ///     "ES256"
    ///   ]
    /// }
    /// ```
    pub fn openid4vp_scheme_static() -> Self {
        // Unwrap safety: unit tested.
        let authorization_endpoint = AuthorizationEndpoint("openid4vp:".parse().unwrap());

        let response_types_supported = ResponseTypesSupported(vec![ResponseType::VpToken]);

        let alg_values_supported = vec!["ES256".to_string()];

        let mut vp_formats_supported = ClaimFormatMap::new();
        vp_formats_supported.insert(
            ClaimFormatDesignation::JwtVpJson,
            ClaimFormatPayload::AlgValuesSupported(alg_values_supported.clone()),
        );
        vp_formats_supported.insert(
            ClaimFormatDesignation::JwtVcJson,
            ClaimFormatPayload::AlgValuesSupported(alg_values_supported.clone()),
        );
        let vp_formats_supported = VpFormatsSupported(vp_formats_supported);

        let request_object_signing_alg_values_supported =
            RequestObjectSigningAlgValuesSupported(alg_values_supported);

        let mut object = UntypedObject::default();

        object.insert(authorization_endpoint);
        object.insert(response_types_supported);
        object.insert(vp_formats_supported);
        object.insert(request_object_signing_alg_values_supported);

        // Unwrap safety: unit tested.
        object.try_into().unwrap()
    }
}

impl From<WalletMetadata> for UntypedObject {
    fn from(value: WalletMetadata) -> Self {
        let mut inner = value.0;
        inner.insert(value.1);
        inner.insert(value.2);
        inner
    }
}

impl TryFrom<UntypedObject> for WalletMetadata {
    type Error = Error;

    fn try_from(value: UntypedObject) -> Result<Self, Self::Error> {
        let authorization_endpoint = value.get().parsing_error()?;
        let vp_formats_supported = value.get().parsing_error()?;
        let response_types_supported = value.get().parsing_error()?;
        let client_id_schemes_supported = value.get().parsing_error().unwrap_or_default();
        let request_object_signing_alg_values_supported =
            value.get().parsing_error().unwrap_or_default();
        let scopes_supported = value.get().parsing_error().unwrap_or_default();
        let subject_syntax_types_supported = value.get().parsing_error().unwrap_or_default();
        let id_token_types_supported = value.get().parsing_error().unwrap_or_default();
        let id_token_signing_alg_values_supported = value.get().parsing_error().unwrap_or_default();

        Ok(Self(
            value,
            authorization_endpoint,
            vp_formats_supported,
            response_types_supported,
            client_id_schemes_supported,
            request_object_signing_alg_values_supported,
            scopes_supported,
            subject_syntax_types_supported,
            id_token_types_supported,
            id_token_signing_alg_values_supported,
        ))
    }
}

impl Deref for WalletMetadata {
    type Target = UntypedObject;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WalletMetadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use super::WalletMetadata;

    #[test]
    fn openid4vp_scheme_static() {
        let expected = serde_json::json!(
          {
            "authorization_endpoint": "openid4vp:",
            "response_types_supported": [
              "vp_token"
            ],
            "vp_formats_supported": {
              "jwt_vp_json": {
                "alg_values_supported": ["ES256"]
              },
              "jwt_vc_json": {
                "alg_values_supported": ["ES256"]
              }
            },
            "request_object_signing_alg_values_supported": [
              "ES256"
            ]
          }
        );

        let wallet_metadata = WalletMetadata::openid4vp_scheme_static();

        assert_eq!(expected, serde_json::to_value(wallet_metadata).unwrap())
    }
}

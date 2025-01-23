use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{}", .0)]
    Internal(anyhow::Error),
    #[error("{}", .0)]
    Protocol(ProtocolError),
}

impl Error {
    pub fn protocol(error_type: ErrorType, description: &str, state: Option<String>) -> Error {
        Error::Protocol(ProtocolError {
            r#type: error_type,
            description: Some(description.to_owned()),
            state,
            source: None,
        })
    }

    pub fn internal(error: anyhow::Error) -> Error {
        Error::Internal(error)
    }

    pub fn protocol_invalid_req(description: &str, state: Option<String>) -> Error {
        Error::Protocol(ProtocolError {
            r#type: ErrorType::InvalidRequest,
            description: Some(description.to_owned()),
            state,
            source: None,
        })
    }

    pub fn protocol_vp_formats_not_supported(description: &str, state:Option<String>) -> Error {
        Error::Protocol(ProtocolError {
            r#type: ErrorType::VpFormatsNotSupported,
            description: Some(description.to_owned()),
            state,
            source: None,
        })
    }

    pub fn protocol_access_denied(description: &str, state: &Option<String>) -> Error {
        Error::Protocol(ProtocolError {
            r#type: ErrorType::AccessDenied,
            description: Some(description.to_owned()),
            state: state.to_owned(),
            source: None,
        })
    }

    pub fn add_source(mut self, source: anyhow::Error) -> Error {
        if let Error::Protocol(ref mut err) = self {
            err.source = Some(source)
        }

        self
    }
}

/// A protocol-specific `oid4vp` error response.
///
/// Those errors are defined in the standard.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response>.
///
/// Should be treated like 400 errors.
///
#[derive(Error, Debug, Deserialize, Serialize)]
pub struct ProtocolError {
    #[serde(rename = "error")]
    pub r#type: ErrorType,
    #[serde(rename = "error_description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    source: Option<anyhow::Error>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidScope,
    InvalidRequest,
    InvalidClient,
    AccessDenied,
    VpFormatsNotSupported,
    InvalidPresentationDefinitionUri,
    InvalidPresentationDefinitionReference,
    InvalidRequestUriMethod,
    WalletUnavailable,
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            ErrorType::InvalidScope => {
                write!(f, "invalid_scope")
            }
            ErrorType::InvalidRequest => {
                write!(f, "invalid_request")
            }
            ErrorType::InvalidClient => {
                write!(f, "invalid_client")
            }
            ErrorType::AccessDenied => {
                write!(f, "access_denied")
            }
            ErrorType::VpFormatsNotSupported => {
                write!(f, "vp_formats_not_supported")
            }
            ErrorType::InvalidPresentationDefinitionUri => {
                write!(f, "invalid_presentation_definition_uri")
            }
            ErrorType::InvalidPresentationDefinitionReference => {
                write!(f, "invalid_presentation_definition_reference")
            }
            ErrorType::InvalidRequestUriMethod => {
                write!(f, "invalid_request_uri_method")
            }
            ErrorType::WalletUnavailable => {
                write!(f, "wallet_unavailable")
            }
        }
    }
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let description = &mut self.description.clone().unwrap_or("".to_owned());
        let state = &mut self.state.clone().unwrap_or("".to_owned());

        if let (Some(source), true) = (&self.source, cfg!(debug_assertions)) {
            description.push_str(&format!(": {source}"));
        }

        write!(f, "{}:{}:{}", self.r#type, description, state)
    }
}

impl From<anyhow::Error> for Error {
    fn from(value: anyhow::Error) -> Self {
        Error::Internal(value)
    }
}

use std::fmt::Debug;

use anyhow::{bail, Result};
use client::Client;
use request_builder::RequestBuilder;
use url::Url;

use crate::core::object::{TypedParameter, UntypedObject};
use crate::utils::{WasmNotSend, WasmNotSync};

pub mod by_reference;
pub mod client;
pub mod request_builder;

/// An OpenID4VP verifier, also known as the client.
#[derive(Debug, Clone)]
pub struct Verifier<C: Client + WasmNotSend + WasmNotSync> {
    client: C,
    default_request_params: UntypedObject,
    submission_endpoint: Option<Url>,
}

impl<C: Client + WasmNotSend + WasmNotSync> Verifier<C> {
    /// Build a new verifier.
    pub fn builder() -> VerifierBuilder<C> {
        VerifierBuilder {
            client: None,
            default_request_params: Default::default(),
            submission_endpoint: None,
        }
    }

    /// Begin building a new authorization request (credential presentation).
    pub fn build_authorization_request(&self) -> RequestBuilder<'_, C> {
        RequestBuilder::new(self)
    }
}

/// Builder struct for [Verifier].
#[derive(Debug, Clone)]
pub struct VerifierBuilder<C: Client + WasmNotSend + WasmNotSync> {
    client: Option<C>,
    default_request_params: UntypedObject,
    submission_endpoint: Option<Url>,
}

impl<C: Client + WasmNotSend + WasmNotSync> VerifierBuilder<C> {
    /// Build the verifier.
    pub async fn build(self) -> Result<Verifier<C>> {
        let Self {
            client,
            default_request_params,
            submission_endpoint,
        } = self;

        let Some(client) = client else {
            bail!("client is required, see `with_client`")
        };

        Ok(Verifier {
            client,
            default_request_params,
            submission_endpoint,
        })
    }

    /// Set default parameters that every
    /// [AuthorizationRequest](crate::core::authorization_request::AuthorizationRequest) will
    /// contain.
    ///
    /// 'client_id' and 'client_id_prefix' are always overridden by the
    /// [Client](crate::verifier::client::Client).
    pub fn with_default_request_parameter<T: TypedParameter>(mut self, t: T) -> Self {
        self.default_request_params.insert(t);
        self
    }

    /// Set the [Client](crate::verifier::client::Client) that the [Verifier] will use to identify
    /// itself to the Wallet.
    pub fn with_client(mut self, client: C) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the [Url] that the [Verifier] will listen at to receive the presentation submission
    /// from the Wallet.
    pub fn with_submission_endpoint(mut self, endpoint: Url) -> Self {
        self.submission_endpoint = Some(endpoint);
        self
    }
}

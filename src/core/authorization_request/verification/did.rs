use crate::core::error::Error;
use crate::core::{
    authorization_request::AuthorizationRequestObject,
    metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
    object::ParsingErrorContext,
};
use anyhow::{Context, Result};
use base64::prelude::*;
use serde_json::{Map, Value as Json};

use ssi::jwk::JWKResolver;

/// Default implementation of request validation for `client_id_scheme` `did`.
pub async fn verify_with_resolver(
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_dids: Option<&[String]>,
    resolver: impl JWKResolver,
) -> Result<(), Error> {
    let state = request_object.state();

    let (headers_b64, _, _) =
        ssi::claims::jws::split_jws(&request_jwt).map_err(|e| Error::internal(e.into()))?;

    let headers_json_bytes = BASE64_URL_SAFE_NO_PAD.decode(headers_b64).map_err(|e| {
        Error::protocol_access_denied("jwt headers were not valid base64url", state.clone())
            .add_source(e.into())
    })?;

    let mut headers =
        serde_json::from_slice::<Map<String, Json>>(&headers_json_bytes).map_err(|e| {
            Error::protocol_access_denied("jwt headers were not valid json", state.clone())
                .add_source(e.into())
        })?;

    let Json::String(alg) = headers.remove("alg").ok_or_else(|| {
        Error::protocol_access_denied("'alg' was missing from jwt headers", state.clone())
    })?
    else {
        return Err(Error::protocol_access_denied(
            "'alg' header of jwt is not a string",
            state.clone(),
        ));
    };

    let supported_algs: RequestObjectSigningAlgValuesSupported =
        wallet_metadata.get().parsing_error()?;

    if !supported_algs.0.contains(&alg) {
        return Err(Error::protocol_access_denied(
            &format!("request was signed with unsupported algorithm: {alg}"),
            state.clone(),
        ));
    }

    let Json::String(kid) = headers
        .remove("kid")
        .context("'kid' was missing from jwt headers")?
    else {
        return Err(Error::protocol_access_denied(
            &format!("'kid' header of jwt is not a string: {alg}"),
            state.clone(),
        ));
    };

    let client_id = request_object.client_id();
    let (did, _f) = kid.split_once('#').ok_or_else(|| {
        Error::protocol_access_denied(
            &format!("expected a DID verification method in 'kid' header, received '{kid}'"),
            state.clone(),
        )
    })?;

    if client_id.get_id() != did {
        return Err(Error::protocol_access_denied(
            &format!(
                "DIDs from 'kid' ({did}) and 'client_id' ({}) do not match",
                client_id.get_full_id()
            ),
            state.clone(),
        ));
    }

    if let Some(dids) = trusted_dids {
        if !dids.iter().any(|trusted_did| trusted_did == did) {
            return Err(Error::protocol_access_denied(
                "'client_id' ({did}) is not in the list of trusted dids",
                state.clone(),
            ));
        }
    }

    let jwk = resolver.fetch_public_jwk(Some(&kid)).await.map_err(|e| {
        Error::protocol_access_denied(
            "unable to resolve verification method from 'kid' header",
            state.clone(),
        )
        .add_source(e.into())
    })?;

    let _: Json = ssi::claims::jwt::decode_verify(&request_jwt, &jwk).map_err(|e| {
        Error::protocol_access_denied("request signature could not be verified", state.clone())
            .add_source(e.into())
    })?;

    Ok(())
}

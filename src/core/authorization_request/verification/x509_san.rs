use anyhow::{bail, Context, Result};
use base64::prelude::*;
use p256::ecdsa::signature::digest::Digest;
use serde_json::{Map, Value as Json};
use ssi::crypto::k256::sha2;
use tracing::debug;
use x509_cert::{
    der::{referenced::OwnedToRef, Decode},
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use crate::{
    core::{
        authorization_request::AuthorizationRequestObject,
        metadata::{parameters::wallet::RequestObjectSigningAlgValuesSupported, WalletMetadata},
        object::ParsingErrorContext,
    },
    verifier::client::X509Variant,
};

use super::verifier::Verifier;

/// Default implementation of request validation for the `x509_hash` and
/// `x509_san_dns` Client Identifier Prefixes.
pub fn validate<V: Verifier>(
    x509_san_variant: X509Variant,
    wallet_metadata: &WalletMetadata,
    request_object: &AuthorizationRequestObject,
    request_jwt: String,
    trusted_roots: Option<&[Certificate]>,
) -> Result<()> {
    let client_id = request_object.client_id().get_id();
    let client_id_source = client_id
        .strip_prefix(&format!("{}:", String::from(x509_san_variant.to_prefix())))
        .unwrap_or(&client_id);
    let (headers_b64, body_b64, sig_b64) = ssi::claims::jws::split_jws(&request_jwt)?;

    let headers_json_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(headers_b64)
        .context("jwt headers were not valid base64url")?;

    let mut headers = serde_json::from_slice::<Map<String, Json>>(&headers_json_bytes)
        .context("jwt headers were not valid json")?;

    let Json::String(alg) = headers
        .remove("alg")
        .context("'alg' was missing from jwt headers")?
    else {
        bail!("'alg' header was not a string")
    };

    let supported_algs: RequestObjectSigningAlgValuesSupported =
        wallet_metadata.get().parsing_error()?;

    if !supported_algs.0.contains(&alg) {
        bail!("request was signed with unsupported algorithm: {alg}")
    }

    let Json::Array(x5chain) = headers
        .remove("x5c")
        .context("'x5c' was missing from jwt headers")?
    else {
        bail!("'x5c' header was not an array")
    };

    let Json::String(b64_x509) = x5chain.first().context("'x5c' was an empty array")? else {
        bail!("'x5c' header was not an array of strings");
    };

    let leaf_cert_der = BASE64_STANDARD_NO_PAD
        .decode(b64_x509.trim_end_matches('='))
        .context("leaf certificate in 'x5c' was not valid base64")?;

    let leaf_cert = Certificate::from_der(&leaf_cert_der)
        .context("leaf certificate in 'x5c' was not valid DER")?;

    ensure_client_id_matches_leaf(
        x509_san_variant,
        client_id_source,
        &leaf_cert,
        &leaf_cert_der,
    )?;

    if let Some(_trusted_roots) = trusted_roots {
        // TODO: Verify chain to root.
    }

    let verifier = V::from_spki(
        leaf_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref(),
        alg,
    )
    .context("unable to parse SPKI")?;

    let payload = [headers_b64.as_bytes(), b".", body_b64.as_bytes()].concat();
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(sig_b64)
        .context("could not decode base64url encoded jwt signature")?;

    verifier
        .verify(&payload, &signature)
        .context("request signature could not be verified")?;

    Ok(())
}

fn ensure_client_id_matches_leaf(
    variant: X509Variant,
    client_id: &str,
    leaf_cert: &Certificate,
    leaf_cert_der: &[u8],
) -> Result<()> {
    match variant {
        X509Variant::Hash => {
            let hash = BASE64_URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(leaf_cert_der));

            if hash != client_id {
                bail!("client_id does not match the hash of the leaf certificate in 'x5c'")
            }
        }
        X509Variant::SanDns => {
            let matches = leaf_cert
                .tbs_certificate
                .filter::<SubjectAltName>()
                .filter_map(|r| match r {
                    Ok((_crit, san)) => Some(san.0.into_iter()),
                    Err(e) => {
                        debug!("unable to parse SubjectAlternativeName from DER: {e}");
                        None
                    }
                })
                .flatten()
                .filter_map(|gn| match gn {
                    GeneralName::DnsName(dns) => Some(dns.to_string()),
                    gn => {
                        debug!("found non-DNS SAN: {gn:?}");
                        None
                    }
                })
                .any(|dns| dns == client_id);

            if !matches {
                bail!("client_id does not match any Subject Alternative Name")
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::{DecodePem, Encode};
    const LEAF_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIUZ0sUbVcHoWEWaz9DcIw3HNDv4mwwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQdmVyaWZpZXIuZXhhbXBsZTAeFw0yNjA3MjUxMzE3NTJaFw0z
NjA3MjIxMzE3NTJaMBsxGTAXBgNVBAMMEHZlcmlmaWVyLmV4YW1wbGUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQfGeYeCA4RI9xmfml8yuB289vgYdplBUPDtlkR
VX5n8ec6c150wgvBJD5etexGbiSrJtlZ5VKI2IuCo3eMlCgpo20wazAdBgNVHQ4E
FgQU9uFMq/NqtsYpwU5bdoAAMmCgYGQwHwYDVR0jBBgwFoAU9uFMq/NqtsYpwU5b
doAAMmCgYGQwGwYDVR0RBBQwEoIQdmVyaWZpZXIuZXhhbXBsZTAMBgNVHRMBAf8E
AjAAMAoGCCqGSM49BAMCA0gAMEUCIQDm4xtRVAZeLVpXtBF+JmZA6G1EgT3hJoLM
olfQxZzr/AIgN0aICEuoH4qkiU5n6zsYrRUGSjxg74hGubPQcUI901Y=
-----END CERTIFICATE-----";
    const LEAF_HASH: &str = "IKC0DWzNRPtrEnSH-5lUfjr2qo2Jicub4x9z32rk_9Y";

    fn leaf() -> (Certificate, Vec<u8>) {
        let cert = Certificate::from_pem(LEAF_PEM).expect("leaf certificate parses");
        let der = cert.to_der().expect("leaf certificate encodes");

        (cert, der)
    }

    fn check(variant: X509Variant, client_id: &str) -> Result<()> {
        let (cert, der) = leaf();

        ensure_client_id_matches_leaf(variant, client_id, &cert, &der)
    }

    #[test]
    fn x509_hash_accepts_the_sha256_of_the_whole_der_certificate() {
        assert!(check(X509Variant::Hash, LEAF_HASH).is_ok());
    }

    #[test]
    fn x509_hash_rejects_a_different_certificates_hash() {
        assert!(check(
            X509Variant::Hash,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
    }

    #[test]
    fn x509_hash_does_not_accept_a_subject_alternative_name() {
        assert!(check(X509Variant::Hash, "verifier.example").is_err());
    }

    #[test]
    fn x509_san_dns_accepts_a_dns_san_entry() {
        assert!(check(X509Variant::SanDns, "verifier.example").is_ok());
    }

    #[test]
    fn x509_san_dns_rejects_another_host() {
        assert!(check(X509Variant::SanDns, "attacker.example").is_err());
    }

    #[test]
    fn x509_san_dns_does_not_accept_the_leaf_hash() {
        assert!(check(X509Variant::SanDns, LEAF_HASH).is_err());
    }
}

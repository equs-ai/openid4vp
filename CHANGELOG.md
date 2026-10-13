# Changelog

All notable changes to this fork are documented here.

This is a fork of [spruceid/openid4vp](https://github.com/spruceid/openid4vp),
diverged at `347814f`.

### Added

- A delegate SD-JWT transaction-data type.
- wasm32 support.

### Changed

- Updated to OpenID4VP 1.0.
- Authorization request and response types reworked for the fetch-then-verify flow.
- `Verifier` is generic over its client; the request signer moved to a
  crate-level `Signer`.
- Published as `equs-openid4vp`; the library target stays `openid4vp`, so `use openid4vp::…` is unchanged.

### Fixed

- `presentation_definition` parsing, and wallet metadata / nonce URL encoding
  when fetching the request object by `POST`.
- `x509_hash` computed over the whole DER certificate, and claim format matching
  requires any algorithm in common rather than all.

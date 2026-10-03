# Security policy

## Reporting a vulnerability

Use [private vulnerability reporting](https://github.com/chromablue-labs/patchwork-rb/security/advisories/new). Do not open a public issue.

Include the gem version, the Ruby version, and the smallest code that demonstrates it. Redact keys and secrets: a generated `OpenSSL::PKey::RSA.new(2048)` and a dummy secret reproduce anything in this gem.

## Supported versions

The latest release. Fixes ship as a new patch version.

## In scope

- Forging or bypassing `Patchwork::Signature.verify`
- Forging, replaying outside the documented window, or widening the claims of a token accepted by `Patchwork::SessionToken.verify` or `Patchwork::BridgeAssertion.verify`
- Any path where `Patchwork::Gateway` or `Patchwork::Rails::Presented` authenticates a request it should refuse
- Two distinct inputs to `Patchwork::Subject` producing one subject string, or one string decoding to two different sets of parts
- Key or secret material reaching a log line, an exception message or `inspect`
- Unbounded work or memory before a request is authenticated

## Known and documented

The request signature covers the method, the path and the raw body, not the query string. A GET tool's arguments are therefore not integrity-protected. This is a property of the signing scheme, not a defect in this gem; the README says so and says what to do about it.

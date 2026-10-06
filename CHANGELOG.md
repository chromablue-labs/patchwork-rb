# Changelog

## 0.1.7 — 2026-10-06

### Added

- **You can require `v2`.** `Signature.verify` and `verify!` take `labels:`, and the gateway takes it too. The default accepts either label, which is what the migration needs. `labels: [Patchwork::Signature::V2]` refuses a signature that does not cover the query.

```ruby
use Patchwork::Gateway,
  resolve: ...,
  labels: [ Patchwork::Signature::V2 ]
```

This is how a GET tool's arguments become protected before `v1` retires. The trade is that it fails against a platform still sending `v1` alone, so turn it on once you know Patchwork sends `v2` to you — which it does for every tool call, the relay mint, the connection probe and webhook deliveries.

Worth being precise about what it buys. With the default, a header carrying both labels verifies through `v1` even when the query has changed, because `v1` does not cover the query. Requiring `v2` is what closes that, and a test pins exactly this difference.

## 0.1.6 — 2026-10-06

### Added

- **A verified call answers with `Patchwork-Sdk: patchwork-rb/<version>`.** The gateway sets it on a call it verified and on its own replies, and `Rails::Presented` sets it on a verified call. A request that falls through to your own auth does not get it, because that is your traffic rather than Patchwork's.

It exists so Patchwork can tell which version a workspace runs. Retiring the `v1` signature label breaks a consumer that only reads `v1`, and without this there is no way to know whether any are left, so the decision would be a guess. Nothing about your integration changes, and the header carries a version and nothing else.

A refused call announces it too. A version is worth knowing even when verification failed.

## 0.1.5 — 2026-10-06

### Added

- **`v2` signatures, which cover the query string.** `v1` covers the method, the path and the body, so a GET tool's arguments ride in the query with no integrity protection. `v2` covers the same with the query exactly as sent. `Signature.verify` accepts either label, and the gateway and `Rails::Presented` pass the query for you.

Patchwork sends both labels during the migration, so this release changes nothing you can observe: a `v1` signature still verifies. Protection for a GET tool's arguments arrives when Patchwork stops sending `v1`.

Two decisions behind it:

- The `v2` payload carries a `v2.` prefix. Without it the two labels would cover identical bytes for a request with no query, and one signature could read as the other.
- `v2` signs the query byte for byte, with no sorting and no re-encoding. This gem already verifies the raw body rather than a re-serialised form, and a normalisation rule is the part that drifts between two implementations. The same parameters in another order are a different signature.

If you verify with the primitives rather than the gateway, pass `query:` to `Signature.verify` — the raw query string, which is `request.query_string` in Rack and Rails. Leave it out and a `v2` value is checked against the bare path, which will not match.

### Changed

- An unknown label in the header is ignored rather than refused, so a later label cannot break this version. A header carrying only an unknown label is still refused.

## 0.1.4 — 2026-10-05

### Added

- **`connection_id` is configuration.** Set it once in `Patchwork.configure` and every minted token carries it as `conn` — including the tokens `Mint.relay` and the gateway's `mint_path` issue. `Mint.relay` also takes `connection_id:` for a one-off.

Before this, neither the relay mint nor the gateway could stamp `conn` at all. An agent with unpinned customer tools could not use either, and had to assemble the mint from `Signature.verify!`, `Mint.relay_subject` and `SessionToken.issue` by hand.

### Tests

- The relay mint now has its own suite, and the gateway's `mint_path` is covered for the first time.

## 0.1.3 — 2026-10-04

### Added

- **`Patchwork::Gateway` takes `health_path:`.** The connection check was only ever matched at `/patchwork/up`, so an app whose routes live under a prefix — `/api/v2/patchwork/up` — had to strip that prefix in a middleware ahead of the gateway. Pass the full path instead. `mint_path:` already worked this way.

Stripping a prefix ahead of the gateway is worth avoiding either way: the signature is verified over the path the request arrived on, because that is the path Patchwork signed. A stripped path makes a signed probe 401, which shows up as *reachable* rather than as an error.

### Documentation

- `base_url` may carry a path prefix, what that means for the signed path, and why `map "/api/v2"` is enough in bare Rack but not in Rails.

## 0.1.2 — 2026-10-03

Documentation. No code changes.

- `/patchwork/up` is documented as a required step and included in the routes example, which previously left it out. Without that route a connection can never report verified.
- The connection check now covers what **verified**, **reachable** and **unreachable** each mean, that the path is fixed and resolved against the connection's `base_url`, that only a `minted` connection can be cryptographically verified, and that a redirect or a 404 is what usually produces *reachable* when *verified* was expected.
- Corrected the request secret rotation order. Patchwork generates that secret and starts signing with the new one as soon as it is rotated, so the rotation and the deploy go together; `previous_request_secret` covers requests already signed with the old secret.

## 0.1.1 — 2026-10-03

Packaging and documentation. No code changes.

- `documentation_uri`, `source_code_uri`, `bug_tracker_uri` and `changelog_uri` resolve. The 0.1.0 links pointed into a repository that is not public.
- README: the Patchwork endpoints are shown as named actions on one controller, with links to the platform guides.

## 0.1.0 — 2026-10-02

First release. Mint the session tokens your frontend presents to Patchwork, verify the tool calls Patchwork makes to your backend, and verify webhook deliveries.

### Added

- `Patchwork.configure` — the signing key, issuer, audience and request secrets in one place. `inspect` redacts all three secrets, so a config that reaches a log line or an error tracker doesn't carry the private key with it.
- `Patchwork::SessionToken` — mint and verify the RS256 token your frontend hands Patchwork.
- `Patchwork::Subject` — validate any subject, or declare a composite format once with `Subject.define` and let `encode`/`decode` enforce the order, the delimiter and the part count.
- `Patchwork::Signature` — the signing scheme itself, both directions, including rotation across two secrets.
- `Patchwork::Gateway` — Rack middleware that verifies the tool calls Patchwork makes to you: signature, then session token, then your own `resolve`. Works in Rails, Sinatra, Hanami or bare Rack, and only loads when Rack is present.
- `Patchwork::Rails::Presented` — the same checks as a controller concern, for when middleware is too broad. Needs `activesupport`, and loads only on `require "patchwork/rails"`.
- `Patchwork::Mint.relay` — answers Patchwork's server-to-server mint, which covers relay connections and every Playground run.
- `Patchwork::Webhook` — verifies deliveries against the webhook endpoint's own secret and parses the event.
- `Patchwork::HealthCheck` — the proof that makes **Test** on a connection report *verified* rather than merely reachable.
- `Patchwork::BridgeAssertion` — issue and verify the signed subject for an MCP login bridge.
- `Patchwork::SigningKey` — publish your JWKS. The `kid` defaults to the key's RFC 7638 thumbprint, so rotating the key rotates the `kid` with it.

### Security

Everything below was found by an adversarial audit before release, reproduced with a runnable proof of concept, and fixed with a regression test.

- Verification hashes the body once and computes one MAC per secret, accepts at most 8 `v1=` values and a 1 KB header, and parses strictly. Before this, a single unauthenticated request with a large body and many candidate signatures cost seconds of CPU.
- A malformed or stale signature header is refused **before the body is read**. Signed bodies are capped at 1 MiB (configurable) and control endpoints at 16 KB.
- A blank or whitespace-only secret raises `ConfigurationError`. An empty string is a valid HMAC key, so accepting one would make every signature forgeable.
- RS256 is pinned against your own public key. HS256 signed with that public key, `alg: none` in any casing, and the `jwk`, `jku` and `kid` headers are all refused.
- A token whose own `exp - iat` exceeds `max_token_lifetime` (900s by default) is refused even with a valid signature.
- Subject validation refuses rather than normalises, and rejects Unicode edge whitespace and control characters. Trimming a trailing space would silently merge two data partitions; CR and LF matter because relay carries the subject in a header.
- `Subject::Format#encode` requires a round trip, so a multi-character delimiter cannot make two different sets of parts produce one subject string.
- A signed request carrying `X-HTTP-Method-Override`, or one `Rack::MethodOverride` has already rewritten, is a 401.
- A truthy-but-empty `resolve` result — an empty relation, an empty string — refuses the request rather than authorising it.
- The `patchwork.*` env keys are cleared on entry on every path, so only the gateway can mark a request as Patchwork's.
- 401 bodies are generic, so they reveal neither your audience nor your issuer.
- The signing key must be an unencrypted RSA private key of at least 2048 bits, parsed with an explicit empty passphrase so an encrypted key errors instead of blocking boot on a prompt.
- The health proof is domain-separated from request signatures, so answering unsigned probes is not a signing oracle.
- The `jwt` floor is `>= 2.10.3`, excluding 3.0.0 through 3.1.2, which are affected by GHSA-c32j-vqhx-rx3x. The gem is not exploitable through that advisory, but a consumer should not resolve to a vulnerable `jwt` because of us.

### Known limitation

The signature covers the method, the path and the raw body — **not the query string** — and Patchwork sends a GET tool's arguments as query parameters. So a GET tool's arguments are not integrity-protected. Give any tool whose arguments matter a `POST` binding, where the arguments travel in the signed body. A `v2=` scheme that covers the query is planned, and will be accepted alongside `v1=` so this version keeps working.

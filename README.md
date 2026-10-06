# patchwork-rb

The Ruby SDK for [Patchwork](https://usepatchwork.co). It mints session tokens for your users, verifies the tool calls Patchwork makes to your backend, and verifies webhook deliveries.

[Documentation](https://docs.usepatchwork.co) · [Changelog](CHANGELOG.md) · [Issues](https://github.com/chromablue-labs/patchwork-rb/issues)

```ruby
# Gemfile
gem "patchwork-rb"
```

Install `patchwork-rb` and `require "patchwork"`. Do not add `gem "patchwork"` — that name belongs to an unrelated gem.

The subject you mint for is an opaque string you choose. Patchwork stores it, partitions threads and memory on it, and hands it back on every tool call, without ever parsing it. Neither does this gem, unless you declare a format (section 2).

## 1. Configure

```ruby
# config/initializers/patchwork.rb
Patchwork.configure do |config|
  config.signing_key    = ENV.fetch("PATCHWORK_SIGNING_KEY")     # RSA private key, PEM or base64 PEM
  config.issuer         = ENV.fetch("PATCHWORK_API_KEY_ID")      # your API key's public id, key_…
  config.audience       = "acme-api"                             # your own API's audience
  config.request_secret = ENV.fetch("PATCHWORK_REQUEST_SECRET")  # the connection's shared secret
end
```

| Setting | Required for | Notes |
| --- | --- | --- |
| `signing_key` | minting, tool calls | Never leaves your server. Patchwork only ever holds the public half. |
| `issuer` | minting, tool calls | Routes a token to your workspace. It identifies a key and authorises nothing. |
| `audience` | minting, tool calls | No default. Tokens carry `["patchwork", audience]`, and tool calls are verified against it. |
| `request_secret` | tool calls, health check | Set `previous_request_secret` during a rotation. |
| `signing_kid` | optional | Defaults to the key's RFC 7638 thumbprint, so a new key gets a new `kid` automatically. |
| `connection_id` | optional | Set it when the agent has unpinned customer tools. A connection UUID, not a name. Minted tokens carry it as `conn`, including the ones the relay mint and the gateway issue. |
| `token_ttl` | optional | Seconds. Defaults to 120. The browser remints as needed. |
| `max_token_lifetime` | optional | Seconds. Defaults to 900. Verification refuses a token whose own `exp - iat` is longer, so a good signature over an absurd expiry is still rejected. `nil` turns the check off. |

A missing setting raises `Patchwork::ConfigurationError` the first time it is needed. So does a blank secret. An empty string is a valid HMAC key, so accepting one would make every signature forgeable.

## 2. Choose your subject

A subject is the partition key for a user's threads and memory. Patchwork stores it byte for byte and never parses it. Pick the smallest unit that must never see another unit's data:

```
"usr_9f2"              one account per person
"usr_9f2:ws_acme"      a person inside one of their workspaces
"slack:T04AB:U0APP"    a Slack user, namespaced by team
"ticket:8821"          a conversation, not a person
"ws_acme"              a whole team, sharing one memory on purpose
```

The [Subjects guide](https://docs.usepatchwork.co/guides/subjects) covers how to choose. Every shape works.

**Single-value subjects** need nothing from the gem. Pass the string.

**Composite subjects** are worth declaring once, so a flipped order or an id containing the delimiter is caught at the call site:

```ruby
# config/initializers/patchwork.rb, next to Patchwork.configure
WorkspaceSubject = Patchwork::Subject.define(:user_id, :workspace_id)

WorkspaceSubject.encode(user_id: user.id, workspace_id: workspace.id)  # => "usr_9f2:ws_acme"
WorkspaceSubject.decode("usr_9f2:ws_acme").workspace_id                # => "ws_acme"
WorkspaceSubject.decode("usr_9f2")                                      # => nil
```

Define as many parts as your boundary needs, with an optional namespace prefix and your own delimiter:

```ruby
Patchwork::Subject.define(:ticket_id, prefix: "ticket")                  # "ticket:8821"
Patchwork::Subject.define(:team_id, :user_id, prefix: "slack")           # "slack:T04AB:U0APP"
Patchwork::Subject.define(:org_id, :user_id, :project_id, delimiter: "|") # "o1|u2|p3"
```

A format fixes the rules:

- **Order comes from the definition.** `encode` is keyword-only, so the order at the call site doesn't matter.
- **A part containing the delimiter is refused** at encode time. Otherwise it would be split wrongly on decode.
- **Empty or whitespace-padded parts are refused.** `"usr_9f2 "` would silently be a different subject, with an empty history.
- **`decode` never guesses.** The prefix and the part count must match exactly, or it returns `nil`. `decode!` raises `Patchwork::UnknownSubject` instead.

Every subject, composed or not, must be a non-empty, valid UTF-8 String with no leading or trailing whitespace (Unicode spaces included) and no control characters. `SessionToken.issue` checks this before it signs anything.

Formats have two more rules:
- **Part names** must be lowercase identifiers, and can't be the name of a Struct method (`hash`, `freeze`, `to_h` and so on).
- **Delimiters** can't contain whitespace. With a delimiter longer than one character, a part that would make the string ambiguous (`"acme:"` with `"::"`) is refused, so each subject string decodes to exactly one set of parts.

If you decode several formats that share a delimiter, try the prefixed ones first: `define(:a, :b)` will also match `"slack:x"`.

## 3. Mint tokens for your users

```ruby
# config/routes.rb
post "patchwork/mint",    to: "patchwork#mint"      # section 3
get  "patchwork/jwks",    to: "patchwork#jwks"      # section 3
post "patchwork/up",      to: "patchwork#up"        # section 5
post "patchwork/webhook", to: "patchwork#webhook"   # section 6
```

`mint` has two callers on one URL, and the signature tells them apart. Your frontend asks for a token for the signed-in user; Patchwork asks, server to server, for a token for a subject it already acts for — that covers relay connections and **every Playground run**. Patchwork's call is a signed `POST` carrying `{"subject": "..."}` and expects a bare `{ token, expires_in }` back. The [Session tokens guide](https://docs.usepatchwork.co/guides/session-tokens) has the wire format, and the [Mint endpoint guide](https://docs.usepatchwork.co/guides/mint-endpoint) covers both branches.

```ruby
class PatchworkController < ApplicationController
  skip_forgery_protection

  def mint
    return relay_mint if request.headers["Patchwork-Signature"].present?

    authenticate_user!
    subject = WorkspaceSubject.encode(user_id: current_user.id, workspace_id: current_workspace.id)

    render json: {
      token: Patchwork::SessionToken.issue(subject: subject),
      expires_in: Patchwork.config.token_ttl
    }
  end

  def jwks
    render json: Patchwork::SigningKey.jwks
  end

  private

  def relay_mint
    render json: Patchwork::Mint.relay(
      body: request.raw_post,
      signature: request.headers["Patchwork-Signature"],
      path: request.path
    ), status: :created
  rescue Patchwork::InvalidSignature
    head :unauthorized
  rescue Patchwork::Mint::BadRequest
    head :bad_request
  end
end
```

Build the subject from server state, never from request params. On the direct branch that is the whole of your authorisation.

Set `connection_id` in your configuration when the agent has unpinned customer tools, and every minted token carries it — the direct branch, the relay branch, and the gateway. `issue` also takes `connection_id:` for a one-off. It is a connection UUID, not a name.

`Mint.relay` mints for exactly the subject Patchwork sent, never a default, and verifies the signature before it reads the subject at all. `jwks` publishes the public half of your signing key, so Patchwork can verify what you minted. Set its URL on your workspace.

If you mount the gateway in section 4, `mint_path: "/patchwork/mint"` makes it answer the relay call before your controller sees it, and you can drop `relay_mint`. Your frontend's unsigned request still reaches `mint`.

## 4. Verify the tool calls Patchwork makes to you

When an agent calls one of your tools, Patchwork sends the request with a `Patchwork-Signature` header and the session token you minted. `Patchwork::Gateway` is Rack middleware that verifies both. It then hands the token's subject to a `resolve` callable, which you write, to decide what the request acts as. The [Tool calls guide](https://docs.usepatchwork.co/guides/tool-calls) describes what Patchwork sends.

```ruby
# config/initializers/patchwork.rb
Rails.application.config.middleware.use Patchwork::Gateway,
  subject: WorkspaceSubject,
  resolve: ->(ref) {
    # Your own records, not the token's say-so.
    Membership.find_by(user_id: ref.user_id, workspace_id: ref.workspace_id)
  }
```

In Sinatra or bare Rack it's the same call: `use Patchwork::Gateway, subject: ..., resolve: ...`.

```ruby
class Api::Tools::OrdersController < ApplicationController
  def index
    membership = request.env["patchwork.principal"]   # whatever resolve returned
    render json: membership.workspace.orders.recent
  end
end
```

**`resolve` is required, and it is where authorisation happens.** A valid token proves you minted it for that subject. It does not prove the pairing is still valid: the user may have left the workspace since. Look the subject up in your own records and return whatever the request should act as. Return `nil` or `false` to refuse. An empty collection or an empty string also refuses, so an accidental `where(...)` that matches nothing can't authorise a request. Return a record, not a relation.

### In a controller instead of middleware

Middleware is the right default: it covers every tool route at once. When you would rather verify per controller, the concern runs the same code in a `before_action`:

```ruby
require "patchwork/rails"

class Api::Tools::OrdersController < ApplicationController
  include Patchwork::Rails::Presented
  patchwork_subject_format WorkspaceSubject

  def index
    render json: patchwork_principal.workspace.orders.recent
  end

  private

  def patchwork_resolve(ref)
    Membership.find_by(user_id: ref.user_id, workspace_id: ref.workspace_id)
  end
end
```

`patchwork_resolve` is the same contract as `resolve` above, and defining it is mandatory — a controller that forgets raises rather than quietly skipping authorisation. `patchwork_subject_format` is optional and matches `subject:`. Verification renders a 401 itself, so an action body only ever runs for a verified call, and `patchwork_subject`, `patchwork_claims` and `patchwork_principal` are available inside it.

Unlike the middleware, a request with no `Patchwork-Signature` is a 401 here rather than a fall-through: you mounted the concern on this controller, so nothing else was expected to arrive.

This is the only part of the gem that needs `activesupport`, and it loads only when you require `patchwork/rails`.

**`subject:` is optional.** With a format, the gateway decodes first and passes `resolve` the decoded parts. A subject in any other shape is a 401, and your code never sees it. Without a format, `resolve` gets the raw string, and you can interpret it however you like:

```ruby
use Patchwork::Gateway, resolve: ->(subject, claims) {
  case subject
  when /\Aticket:(\d+)\z/ then Ticket.find_by(id: $1)
  when /\Ajob:/           then :system
  end
}
```

`resolve` can take `(subject)` or `(subject, claims)`. Any object that responds to `call` works.

A verified call answers with `Patchwork-Sdk: patchwork-rb/<version>`, so Patchwork can tell which version you run and retire an old signature label on evidence rather than a guess. A request that falls through to your own auth does not carry it.

After a successful call, the request env carries:

| Key | Value |
| --- | --- |
| `patchwork.principal` | what `resolve` returned |
| `patchwork.subject` | the raw `sub` string |
| `patchwork.claims` | the verified token claims |

Failure behaviour:

- **Requests without a `Patchwork-Signature`** pass straight through to your own auth, untouched. The gateway doesn't read their bodies.
- **Anything that fails after the signature is present** returns a 401 with a JSON error and never reaches your app. This covers a bad or stale signature, a missing, forged, expired or wrong-audience token, a subject in the wrong format, and a `resolve` that refuses.
- **A missing `request_secret`** raises instead of rejecting quietly, so a broken deploy shows up as errors rather than as silently locked-out tools.
- **A signed body over `max_body_bytes`** (1 MiB by default) is a 413, and the gateway reads no more than the limit. A malformed or stale signature header is refused before the body is read at all.
- **401 bodies are generic** (`invalid signature`, `invalid token`, `subject not authorized`), so they don't reveal your audience or issuer.
- **A signed request with no bearer token** is a 401, unless it is the relay mint above. Patchwork sends one only for the mint and for a Patch dry-run started without a session token.

### What the signature does and doesn't cover

A signature carries a label. `v1` covers the method, the path and the raw body. `v2` covers the same with the query string, exactly as sent. The scheme is specified in the [Signing guide](https://docs.usepatchwork.co/guides/signing).

The gateway and the concern verify either label, and pass the query for you. If you verify with the primitives instead, pass `query:` — the raw query string, `request.query_string` in Rack and Rails. Leave it out and a `v2` value is checked against the bare path, which will not match.

**A GET tool's arguments are still not protected yet.** Patchwork sends both labels while consumers upgrade, and `v1` does not cover the query, so altering a GET tool's arguments in flight still passes. That closes when Patchwork stops sending `v1`. Until then, give any tool whose arguments matter — ids, amounts, anything that writes — a `POST` binding, where the arguments travel in the signed body.

The signed path is the one your app sees. If a proxy rewrites paths before your app does, mount the gateway where the original path is still intact.

**Method overrides are refused.** A signed request that carries `X-HTTP-Method-Override`, or that `Rack::MethodOverride` has already rewritten, is a 401. Patchwork never sends one, and the header isn't signed.

### Replays

A signature is valid for 300 seconds, and a captured request can be replayed inside that window. For tools with side effects, pass a `replay_guard`. It is called with a key and a TTL, and must return truthy only the first time it sees that key:

```ruby
Rails.application.config.middleware.use Patchwork::Gateway,
  resolve: ...,
  replay_guard: ->(key, ttl) { Rails.cache.write(key, true, unless_exist: true, expires_in: ttl) }
```

Use a cache that every app process shares. A per-process cache only stops replays that land on the same process.

## 5. Verify the connection

Patchwork POSTs a nonce to `/patchwork/up` and expects back a proof only your request secret can compute. Answering it is what makes **Test** on a connection report **verified** instead of merely **reachable**.

The path is fixed, and resolved against the connection's `base_url`. If `base_url` is `https://api.acme.com`, Patchwork probes `https://api.acme.com/patchwork/up`.

The gateway answers it, including when mounted under a prefix. Without the gateway, it is another action on the same controller:

```ruby
def up
  render json: Patchwork::HealthCheck.respond(body: request.raw_post)
rescue Patchwork::HealthCheck::BadRequest
  head :bad_request
end
```

Pass `health_check: false` to own the route while still using the gateway for tool calls.

Leave the route unauthenticated. The proof is domain-separated from request signatures, so answering an unsigned probe cannot help anyone forge one.

| Test says | Means |
| --- | --- |
| **verified** | The proof matched your request secret. The only result that confirms the secret itself. |
| **reachable** | Something answered, but the proof was missing or wrong — or the connection's auth mode is not `minted`, which is the only mode that can be cryptographically verified. |
| **unreachable** | Nothing answered. |

Two things produce **reachable** when you expect **verified**:

- **A redirect.** Patchwork does not follow it, because the signature covers the original path. Point `base_url` at the final URL, and check https, `www`, and the trailing slash.
- **A 404**, which means `base_url` is not your API root.

Rotation does not break this. Your proof is computed with your current request secret, and Patchwork accepts a proof computed with either its current or its previous one — so `/patchwork/up` keeps reporting verified on both sides of a rotation.

## 6. Verify webhooks

Webhooks use the same signing scheme, keyed with the **webhook endpoint's own secret**, not the request secret. The [Events guide](https://docs.usepatchwork.co/guides/events) lists the event types.

Deliveries land on the same controller:

```ruby
def webhook
  event = Patchwork::Webhook.verify!(
    body: request.raw_post,
    signature: request.headers["Patchwork-Signature"],
    secret: ENV.fetch("PATCHWORK_WEBHOOK_SECRET"),
    path: "/patchwork/webhook"
  )

  case event.type
  when "run.completed" then FulfilJob.perform_later(event.run_id)
  when "run.failed"    then alert(event.data)
  end

  head :ok
rescue Patchwork::InvalidSignature
  head :unauthorized
end
```

- **Read the raw body.** `request.raw_post` is the signed bytes. Re-serialised params are not.
- **Pass the path you registered.** A full URL works too. Use the registered path even if a proxy rewrites it.
- **Rotate with `secrets: [new, old]`** instead of `secret:`.
- **Deduplicate on `event.id`.** A delivery can arrive more than once.

`verify!` raises `Patchwork::InvalidSignature`, or its subclass `Patchwork::StaleSignature`. `verify` returns `nil` instead.

## 7. Rotating secrets and keys

**Request secret:** Patchwork generates this one, so you copy it rather than choose it. Rotate it in your workspace settings, set the new value as `request_secret`, move the value it replaced to `previous_request_secret`, and deploy.

Do the rotation and the deploy together. Patchwork starts signing with the new secret the moment you rotate, so a consumer still holding only the old one will refuse tool calls. `previous_request_secret` exists to cover requests that were already signed with the old secret, not to give you a long overlap. Drop it on your next deploy.

**Signing key:** serve both public keys from your JWKS, and switch `signing_key` once Patchwork has fetched the new set. Never remove the old key first. With `signing_kid` unset, each key's `kid` is its thumbprint, so the two can't collide. To serve more than one key, build the document yourself from `Patchwork::SigningKey.public_jwk` plus the previous one.

## MCP login bridge

If you export an agent over MCP, Patchwork sends your user to a login bridge you host, and the bridge hands back a signed subject. It is signed with the same key you mint with:

Route `get "patchwork/bridge", to: "patchwork#bridge"` and add the action alongside the others:

```ruby
def bridge
  authenticate_user!
  subject = WorkspaceSubject.encode(user_id: current_user.id, workspace_id: chosen_workspace.id)
  assertion = Patchwork::BridgeAssertion.issue(
    subject: subject,
    nonce: params[:state],
    audience: PATCHWORK_CALLBACK
  )

  redirect_to "#{PATCHWORK_CALLBACK}?state=#{params[:state]}&assertion=#{assertion}",
              allow_other_host: true
end
```

`allow_other_host:` is required — the redirect leaves your domain.

Authenticate the user first, and bake the workspace choice into the subject. The assertion is bound to the `state` nonce and the callback audience, and lives 120 seconds at most. That ceiling is enforced at the callback, so asking for longer raises.

## Errors

| Error | Means |
| --- | --- |
| `Patchwork::ConfigurationError` | A required setting or secret is missing or blank, or the signing key is not an unencrypted RSA private key of at least 2048 bits. Treat it as a deploy bug. |
| `Patchwork::InvalidSignature` | The HMAC did not match any configured secret. |
| `Patchwork::StaleSignature` | The signature timestamp is outside the 300-second window. It subclasses `InvalidSignature`. |
| `Patchwork::InvalidToken` | The token was forged, expired, for another audience or issuer, or had no usable `sub`. |
| `Patchwork::UnknownSubject` | A subject didn't match its declared format, or `resolve` refused it. |
| `Patchwork::LifetimeExceeded` | The token's own lifetime is longer than `max_token_lifetime`. It subclasses `InvalidToken`. |
| `ArgumentError` | A subject you tried to mint or encode breaks the rules in section 2. |

All of them except `ArgumentError` inherit from `Patchwork::Error`. None of them carries key material in its message.

## Lower level

The primitives are public if you need to sign or verify outside Rack:

```ruby
Patchwork::Signature.header(secrets: [secret], timestamp: Time.now.to_i, method: "POST", path: "/v1/runs", body: body)
Patchwork::Signature.verify!(secrets: [current, previous], header: header, method: "POST", path: path, body: raw_body)
Patchwork::SessionToken.verify(token)   # => claims, or raises Patchwork::InvalidToken
```

## Compatibility

Ruby 3.1+. One runtime dependency: `jwt` (>= 2.10.3, < 4, excluding 3.0.0–3.1.2, which are affected by GHSA-c32j-vqhx-rx3x). `Patchwork::Gateway` also needs `rack`, and is only defined when Rack is loaded. It works with any Rack app: Rails, Sinatra, Hanami or bare Rack. `Patchwork::Rails::Presented` needs `activesupport` and loads only when you require `patchwork/rails`.

## Support

Bugs and questions: [github.com/chromablue-labs/patchwork-rb/issues](https://github.com/chromablue-labs/patchwork-rb/issues). The platform documentation is at [docs.usepatchwork.co](https://docs.usepatchwork.co).

## Licence

MIT.

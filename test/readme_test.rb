require "test_helper"
require "rack/test"

# Walks the README top to bottom as a consumer would, so the documented flow
# cannot drift from the code without a failing test.
class ReadmeTest < Minitest::Test
  include TestConfig
  include Rack::Test::Methods

  WorkspaceSubject = Patchwork::Subject.define(:user_id, :workspace_id)
  MEMBERSHIPS = [ { user_id: "usr_9f2", workspace_id: "ws_acme" } ].freeze

  def setup
    configure_patchwork(signing_kid: nil)
  end

  def app
    tools = ->(env) { [ 200, { "content-type" => "application/json" }, [ JSON.generate(env["patchwork.principal"]) ] ] }

    Patchwork::Gateway.new(
      tools,
      subject: WorkspaceSubject,
      resolve: ->(ref) { MEMBERSHIPS.find { |m| m == { user_id: ref.user_id, workspace_id: ref.workspace_id } } }
    )
  end

  def test_mint_then_serve_a_tool_call_then_take_a_webhook
    # 3. Mint for the signed-in user, from server state.
    subject = WorkspaceSubject.encode(user_id: "usr_9f2", workspace_id: "ws_acme")
    token = Patchwork::SessionToken.issue(subject: subject)
    assert_equal "usr_9f2:ws_acme", subject

    # The JWKS names the same kid the token carries.
    _, token_header = JWT.decode(token, nil, false)
    assert_equal Patchwork::SigningKey.jwks[:keys].first[:kid], token_header["kid"]

    # 4. Patchwork presents that token back on a tool call.
    body = '{"tool":"orders.recent"}'
    header "Patchwork-Signature", Patchwork::Signature.header(
      secrets: [ "whsec_current" ], timestamp: Time.now.to_i, method: "POST", path: "/api/tools/orders", body: body
    )
    header "Authorization", "Bearer #{token}"
    post "/api/tools/orders", body

    assert_equal 200, last_response.status
    assert_equal({ "user_id" => "usr_9f2", "workspace_id" => "ws_acme" }, JSON.parse(last_response.body))

    # 6. A webhook, keyed with the endpoint's own secret.
    delivery = JSON.generate("id" => "evt_1", "type" => "run.completed", "run_id" => "run_1")
    event = Patchwork::Webhook.verify!(
      body: delivery,
      signature: Patchwork::Signature.header(
        secrets: [ "whsec_endpoint" ], timestamp: Time.now.to_i, method: "POST", path: "/hooks/patchwork", body: delivery
      ),
      secret: "whsec_endpoint",
      path: "/hooks/patchwork"
    )
    assert_equal "run_1", event.run_id
  end

  def test_the_login_bridge_hands_back_a_subject_the_callback_accepts
    callback = "https://api.usepatchwork.co/v1/mcp/callback"
    subject = WorkspaceSubject.encode(user_id: "usr_9f2", workspace_id: "ws_acme")

    assertion = Patchwork::BridgeAssertion.issue(
      subject: subject, nonce: "state-xyz", audience: callback
    )

    claims = Patchwork::BridgeAssertion.verify(assertion, audience: callback, nonce: "state-xyz")
    assert_equal "usr_9f2:ws_acme", claims["sub"]
    assert_equal WorkspaceSubject.decode(claims["sub"]).workspace_id, "ws_acme"

    assert_raises(ArgumentError) do
      Patchwork::BridgeAssertion.issue(subject: subject, nonce: "state-xyz", audience: callback, ttl: 300)
    end
  end
end

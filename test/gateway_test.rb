require "test_helper"
require "rack/test"

class GatewayTest < Minitest::Test
  include TestConfig
  include Rack::Test::Methods

  MEMBERSHIPS = { "usr_1" => [ "ws_1" ] }.freeze
  Membership = Patchwork::Subject.define(:user_id, :workspace_id)

  def setup
    configure_patchwork
    @downstream_hits = 0
    @seen = nil
    @options = {
      subject: Membership,
      resolve: ->(ref) { { user_id: ref.user_id, workspace_id: ref.workspace_id } if MEMBERSHIPS.fetch(ref.user_id, []).include?(ref.workspace_id) }
    }
  end

  def app
    inner = lambda do |env|
      @downstream_hits += 1
      @seen = env
      [ 200, { "content-type" => "text/plain" }, [ "downstream" ] ]
    end

    Patchwork::Gateway.new(inner, **@options)
  end

  def signed_post(path: "/api/tools/lookup", body: '{"q":1}', subject: "usr_1:ws_1",
                  secret: "whsec_current", token: :valid, timestamp: Time.now.to_i)
    bearer = token == :valid ? Patchwork::SessionToken.issue(subject: subject) : token
    signature = Patchwork::Signature.header(
      secrets: [ secret ], timestamp: timestamp, method: "POST", path: path, body: body
    )

    header "Patchwork-Signature", signature
    header "Authorization", bearer ? "Bearer #{bearer}" : nil
    header "Content-Type", "application/json"
    post path, body
  end

  def assert_rejected
    assert_equal 401, last_response.status
    assert_equal 0, @downstream_hits, "a rejected call must never reach the app"
  end

  def test_passes_through_when_there_is_no_patchwork_signature
    post "/api/tools/lookup", '{"q":1}'

    assert_equal 200, last_response.status
    assert_equal 1, @downstream_hits, "an unsigned request must fall through to the app's own auth"
    assert_nil @seen[Patchwork::Gateway::PRINCIPAL_KEY]
  end

  def test_a_valid_call_reaches_the_app_with_the_principal_resolved
    signed_post

    assert_equal 200, last_response.status
    assert_equal "usr_1:ws_1", @seen[Patchwork::Gateway::SUBJECT_KEY]
    assert_equal({ user_id: "usr_1", workspace_id: "ws_1" }, @seen[Patchwork::Gateway::PRINCIPAL_KEY])
    assert_equal "pk_test_client", @seen[Patchwork::Gateway::CLAIMS_KEY]["iss"]
  end

  def test_without_a_format_resolve_receives_the_raw_subject_and_the_claims
    received = nil
    @options = { resolve: ->(subject, claims) { received = [ subject, claims["iss"] ]; :ticket_owner } }

    signed_post(subject: "ticket:8821")

    assert_equal 200, last_response.status
    assert_equal [ "ticket:8821", "pk_test_client" ], received
    assert_equal :ticket_owner, @seen[Patchwork::Gateway::PRINCIPAL_KEY]
  end

  def test_any_callable_works_as_resolve
    resolver = Class.new { def call(subject, _claims) = "resolved:#{subject}" }.new
    @options = { resolve: resolver }

    signed_post(subject: "job:nightly-recon")

    assert_equal "resolved:job:nightly-recon", @seen[Patchwork::Gateway::PRINCIPAL_KEY]
  end

  def test_resolve_returning_nil_or_false_is_401
    [ nil, false ].each do |verdict|
      @downstream_hits = 0
      @options = { resolve: ->(_subject) { verdict } }
      @_rack_test_sessions = nil

      signed_post
      assert_rejected
    end
  end

  def test_a_valid_token_for_a_workspace_the_user_does_not_belong_to_is_401
    signed_post(subject: "usr_1:ws_99")

    assert_rejected
  end

  def test_a_subject_not_in_the_declared_format_is_401_and_resolve_is_never_called
    called = false
    @options = { subject: Membership, resolve: ->(_ref) { called = true } }

    signed_post(subject: "ticket:8821:extra")

    assert_rejected
    refute called, "resolve must not see a subject the format did not decode"
  end

  def test_a_bad_signature_is_401_and_never_falls_through
    signed_post(secret: "wrong-secret")

    assert_rejected
  end

  def test_a_stale_signature_is_401
    signed_post(timestamp: Time.now.to_i - 3600)

    assert_rejected
  end

  def test_a_signature_over_a_different_body_is_401
    path = "/api/tools/lookup"
    signature = Patchwork::Signature.header(
      secrets: [ "whsec_current" ], timestamp: Time.now.to_i, method: "POST", path: path, body: '{"q":1}'
    )
    header "Patchwork-Signature", signature
    header "Authorization", "Bearer #{Patchwork::SessionToken.issue(subject: 'usr_1:ws_1')}"
    post path, '{"q":"tampered"}'

    assert_rejected
  end

  def test_the_previous_secret_is_accepted_during_rotation
    configure_patchwork(request_secret: "whsec_new", previous_request_secret: "whsec_current")

    signed_post(secret: "whsec_current")

    assert_equal 200, last_response.status
  end

  def test_a_valid_signature_with_no_token_is_401
    signed_post(token: nil)

    assert_rejected
  end

  def test_a_valid_signature_with_a_forged_token_is_401
    other = OpenSSL::PKey::RSA.generate(2048)
    forged = JWT.encode(
      { iss: "pk_test_client", aud: [ "patchwork", "test-api" ],
        sub: "usr_1:ws_1", exp: Time.now.to_i + 300 }, other, "RS256"
    )

    signed_post(token: forged)

    assert_rejected
  end

  def test_no_request_secret_configured_fails_loudly_rather_than_rejecting_quietly
    configure_patchwork(request_secret: nil)

    assert_raises(Patchwork::ConfigurationError) { signed_post(secret: "anything") }
  end

  def test_resolve_is_required_and_must_be_callable
    assert_raises(ArgumentError) { Patchwork::Gateway.new(->(_env) {}) }
    assert_raises(ArgumentError) { Patchwork::Gateway.new(->(_env) {}, resolve: "nope") }
    assert_raises(ArgumentError) { Patchwork::Gateway.new(->(_env) {}, resolve: ->(_s) { true }, subject: "nope") }
  end

  def test_the_health_endpoint_returns_a_proof
    body = JSON.generate("nonce" => "n0nce", "issued_at" => Time.now.to_i)
    signature = Patchwork::Signature.header(
      secrets: [ "whsec_current" ], timestamp: Time.now.to_i, method: "POST",
      path: Patchwork::HealthCheck::PATH, body: body
    )

    header "Patchwork-Signature", signature
    post Patchwork::HealthCheck::PATH, body

    assert_equal 200, last_response.status
    parsed = JSON.parse(last_response.body)
    assert_equal "n0nce", parsed["nonce"]
    assert_equal Patchwork::HealthCheck.proof(secret: "whsec_current", nonce: "n0nce"), parsed["proof"]
    assert_equal 0, @downstream_hits
  end

  def test_the_health_endpoint_rejects_a_bad_signature
    body = JSON.generate("nonce" => "n0nce")
    signature = Patchwork::Signature.header(
      secrets: [ "wrong" ], timestamp: Time.now.to_i, method: "POST",
      path: Patchwork::HealthCheck::PATH, body: body
    )

    header "Patchwork-Signature", signature
    post Patchwork::HealthCheck::PATH, body

    assert_equal 401, last_response.status
  end

  NAMESPACED = "/api/v2/patchwork/up".freeze

  def health_signature(path:, secret: "whsec_current", body: nil)
    Patchwork::Signature.header(
      secrets: [ secret ], timestamp: Time.now.to_i, method: "POST", path: path, body: body
    )
  end

  def test_the_health_endpoint_can_live_under_a_namespace
    @options[:health_path] = NAMESPACED
    body = JSON.generate("nonce" => "n0nce")

    header "Patchwork-Signature", health_signature(path: NAMESPACED, body: body)
    post NAMESPACED, body

    assert_equal 200, last_response.status
    assert_equal Patchwork::HealthCheck.proof(secret: "whsec_current", nonce: "n0nce"),
                 JSON.parse(last_response.body)["proof"]
    assert_equal 0, @downstream_hits
  end

  # The signed path is the one Patchwork sent, never the configured one. A
  # middleware that strips the namespace instead of moving it into SCRIPT_NAME
  # would sign over "/patchwork/up" and must be refused.
  def test_a_namespaced_health_endpoint_verifies_over_the_path_patchwork_signed
    @options[:health_path] = NAMESPACED
    body = JSON.generate("nonce" => "n0nce")

    header "Patchwork-Signature", health_signature(path: Patchwork::HealthCheck::PATH, body: body)
    post NAMESPACED, body

    assert_equal 401, last_response.status
    assert_equal 0, @downstream_hits
  end

  def test_configuring_a_namespace_stops_the_default_path_answering
    @options[:health_path] = NAMESPACED

    post Patchwork::HealthCheck::PATH, JSON.generate("nonce" => "n0nce")

    assert_equal 1, @downstream_hits, "an unclaimed path belongs to the app"
  end

  def test_the_health_endpoint_answers_when_mounted_under_a_script_name
    body = JSON.generate("nonce" => "n0nce")
    env = Rack::MockRequest.env_for(
      NAMESPACED,
      method: "POST",
      input: body,
      "SCRIPT_NAME" => "/api/v2",
      "PATH_INFO" => "/patchwork/up",
      "HTTP_PATCHWORK_SIGNATURE" => health_signature(path: NAMESPACED, body: body)
    )

    status, _headers, response = app.call(env)

    assert_equal 200, status
    assert_equal Patchwork::HealthCheck.proof(secret: "whsec_current", nonce: "n0nce"),
                 JSON.parse(response.first)["proof"]
  end

  def test_health_path_must_be_absolute
    assert_raises(ArgumentError) do
      Patchwork::Gateway.new(->(_env) {}, resolve: ->(_s) { true }, health_path: "patchwork/up")
    end
  end

  SDK = "patchwork-rb/#{Patchwork::VERSION}".freeze

  def test_requiring_v2_refuses_a_call_signed_only_with_v1
    @options[:labels] = [ Patchwork::Signature::V2 ]
    signed_post

    assert_equal 401, last_response.status
    assert_equal 0, @downstream_hits
  end

  def test_labels_must_name_a_known_version
    assert_raises(ArgumentError) do
      Patchwork::Gateway.new(->(_env) {}, resolve: ->(_s) { true }, labels: [ "v9" ])
    end
  end


  def test_a_verified_call_announces_the_sdk_version
    signed_post

    assert_equal 200, last_response.status
    assert_equal SDK, last_response.headers[Patchwork::SDK_HEADER]
  end

  def test_a_request_that_falls_through_announces_nothing
    post "/api/tools/lookup", '{"q":1}'

    assert_equal 1, @downstream_hits
    assert_nil last_response.headers[Patchwork::SDK_HEADER],
      "an unsigned request is the consumer's own traffic, not Patchwork's"
  end

  def test_a_refusal_still_announces_the_version
    signed_post(secret: "wrong-secret")

    assert_equal 401, last_response.status
    assert_equal SDK, last_response.headers[Patchwork::SDK_HEADER],
      "a version is worth knowing even when verification failed"
  end

  MINT_PATH = "/patchwork/mint".freeze

  def mint_through_gateway(subject: "usr_1:ws_1")
    @options[:mint_path] = MINT_PATH
    body = JSON.generate("subject" => subject)

    header "Patchwork-Signature", Patchwork::Signature.header(
      secrets: [ "whsec_current" ], timestamp: Time.now.to_i, method: "POST", path: MINT_PATH, body: body
    )
    post MINT_PATH, body
  end

  def test_the_gateway_answers_the_relay_mint
    mint_through_gateway

    assert_equal 201, last_response.status
    parsed = JSON.parse(last_response.body)
    claims = JWT.decode(parsed["token"], TEST_RSA_KEY.public_key, true, algorithms: [ "RS256" ]).first
    assert_equal "usr_1:ws_1", claims["sub"]
    assert_equal 0, @downstream_hits
  end

  def test_the_relay_mint_stamps_the_configured_connection
    configure_patchwork(connection_id: "conn-abc")
    mint_through_gateway

    assert_equal 201, last_response.status
    parsed = JSON.parse(last_response.body)
    claims = JWT.decode(parsed["token"], TEST_RSA_KEY.public_key, true, algorithms: [ "RS256" ]).first
    assert_equal "conn-abc", claims["conn"]
  end

  def test_an_unsigned_mint_falls_through_to_the_app
    @options[:mint_path] = MINT_PATH

    post MINT_PATH, JSON.generate("subject" => "usr_1:ws_1")

    assert_equal 1, @downstream_hits, "the consumer's own frontend mint is not the gateway's"
  end

  def test_the_health_endpoint_can_be_turned_off
    @options[:health_check] = false

    post Patchwork::HealthCheck::PATH, JSON.generate("nonce" => "n0nce")

    assert_equal 1, @downstream_hits
  end

  def test_an_error_response_does_not_leak_key_material
    signed_post(secret: "wrong-secret")

    refute_includes last_response.body, "whsec_current"
    refute_includes last_response.body, "PRIVATE"
  end

  def test_the_downstream_app_can_still_read_the_body
    body = '{"q":1}'
    signed_post(body: body)

    assert_equal 200, last_response.status
    assert_equal body, @seen["rack.input"].read, "the gateway must hand the app the body it read to verify"
  end

  def test_an_unsigned_request_body_is_not_read_by_the_gateway
    input = StringIO.new('{"q":1}')
    def input.read(*) = raise("the gateway read a body it had no reason to")

    status, = app.call(Rack::MockRequest.env_for("/upload", method: "POST", input: input))

    assert_equal 200, status
  end
end

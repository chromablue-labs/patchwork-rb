require "test_helper"
require "rack/test"
require "benchmark"

# One test per finding from the ENG-91 security audit. Each fails against the
# code the finding was reported on.
class SecurityTest < Minitest::Test
  include TestConfig
  include Rack::Test::Methods

  def setup
    configure_patchwork
    @hits = 0
    @seen = nil
    @options = { resolve: ->(subject) { "principal:#{subject}" } }
    @stack = nil
  end

  def app
    inner = lambda do |env|
      @hits += 1
      @seen = env
      [ 200, { "content-type" => "text/plain" }, [ "app" ] ]
    end
    gateway = Patchwork::Gateway.new(inner, **@options)
    @stack ? @stack.call(gateway) : gateway
  end

  def sign(path:, body:, method: "POST", secret: "whsec_current", timestamp: Time.now.to_i)
    Patchwork::Signature.header(secrets: [ secret ], timestamp: timestamp, method: method, path: path, body: body)
  end

  def signed(path: "/tools/x", body: '{"q":1}', subject: "usr_1", token: :valid, **rest)
    header "Patchwork-Signature", sign(path: path, body: body, **rest)
    bearer = token == :valid ? Patchwork::SessionToken.issue(subject: subject) : token
    header "Authorization", "Bearer #{bearer}" if bearer
    post path, body
  end

  # --- Signature: pre-auth CPU amplification -------------------------------

  def test_many_v1_candidates_are_refused_without_hashing_the_body_per_candidate
    body = "x" * 500_000
    t = Time.now.to_i
    header = "t=#{t}," + Array.new(2000) { "v1=#{'0' * 64}" }.join(",")

    elapsed = Benchmark.realtime do
      assert_equal :bad, Patchwork::Signature.verify(secrets: %w[a b], header: header, method: "POST", path: "/x", body: body)
    end
    assert_operator elapsed, :<, 0.05, "2000 candidates must not cost 2000 body hashes"
  end

  def test_a_header_at_the_candidate_cap_still_hashes_the_body_once
    body = "x" * 2_000_000
    t = Time.now.to_i
    good = Patchwork::Signature.sign(secret: "whsec_current", timestamp: t, method: "POST", path: "/x", body: body)
    header = "t=#{t}," + (Array.new(Patchwork::Signature::MAX_SIGNATURES - 1) { "v1=#{'0' * 64}" } + [ "v1=#{good}" ]).join(",")

    assert_equal :ok, Patchwork::Signature.verify(secrets: %w[whsec_current other], header: header, method: "POST", path: "/x", body: body)
  end

  def test_malformed_headers_are_refused_structurally
    t = Time.now.to_i
    [ "", "x", "v1=#{'a' * 64}", "t=#{t}", "t=#{t},t=#{t},v1=#{'a' * 64}", "t=#{t}abc,v1=#{'a' * 64}",
      "t=+#{t},v1=#{'a' * 64}", "t=#{t},v1=#{'a' * 64}#{',x' * 600}" ].each do |header|
      assert_nil Patchwork::Signature.parse(header), "parsed #{header[0, 60].inspect}"
    end
  end

  def test_the_gateway_rejects_a_bad_header_before_reading_the_body
    input = StringIO.new("x" * 10)
    def input.read(*) = raise("read the body of a request with a malformed signature")

    %w[garbage t=1,v1=00].each do |header|
      status, = app.call(Rack::MockRequest.env_for("/tools/x", method: "POST", input: input, "HTTP_PATCHWORK_SIGNATURE" => header))
      assert_equal 401, status
    end
  end

  # --- Gateway: unbounded body buffering -----------------------------------

  def test_an_oversized_signed_body_is_413_and_never_fully_read
    @options[:max_body_bytes] = 1024
    signed(body: "x" * 4096)

    assert_equal 413, last_response.status
    assert_equal 0, @hits
  end

  def test_the_health_check_caps_its_body
    header "Content-Type", "application/json"
    post Patchwork::HealthCheck::PATH, JSON.generate("nonce" => "n", "pad" => "x" * 100_000)

    assert_equal 413, last_response.status
  end

  # --- Gateway: env injection and method override --------------------------

  def test_pre_existing_patchwork_keys_never_reach_the_app_on_an_unsigned_request
    @stack = ->(gateway) { ->(env) { env["patchwork.principal"] = :admin; env["patchwork.subject"] = "usr_admin"; gateway.call(env) } }

    post "/tools/x", "{}"

    assert_equal 1, @hits
    assert_nil @seen["patchwork.principal"]
    assert_nil @seen["patchwork.subject"]
  end

  def test_an_override_header_on_a_signed_request_is_refused_whatever_the_mount_order
    inner = ->(env) { @hits += 1; @seen = env; [ 200, {}, [ "app" ] ] }
    body = '{"q":1}'
    orders = {
      "override after gateway" => Patchwork::Gateway.new(Rack::MethodOverride.new(inner), **@options),
      "override before gateway" => Rack::MethodOverride.new(Patchwork::Gateway.new(inner, **@options))
    }

    orders.each do |name, stack|
      @hits = 0
      env = Rack::MockRequest.env_for("/tools/x", method: "POST", input: body,
        "HTTP_PATCHWORK_SIGNATURE" => sign(path: "/tools/x", body: body),
        "HTTP_AUTHORIZATION" => "Bearer #{Patchwork::SessionToken.issue(subject: 'usr_1')}",
        "HTTP_X_HTTP_METHOD_OVERRIDE" => "DELETE")
      status, = stack.call(env)

      assert_equal 401, status, name
      assert_equal 0, @hits, "#{name}: a verified POST reached the app as #{@seen && @seen['REQUEST_METHOD']}"
    end
  end

  # --- Gateway: fail-closed resolve ----------------------------------------

  def test_an_empty_collection_or_empty_string_from_resolve_is_refused
    [ [], {}, "" ].each do |verdict|
      @hits = 0
      @options = { resolve: ->(_s) { verdict } }
      @_rack_test_sessions = nil
      signed

      assert_equal 401, last_response.status, "authorized on #{verdict.inspect}"
      assert_equal 0, @hits
    end
  end

  def test_resolve_with_keyword_or_splat_signatures_gets_the_claims
    [ ->(s, claims) { "#{s}/#{claims['iss']}" },
      ->(s, *rest) { "#{s}/#{rest.first['iss']}" },
      proc { |s, claims| "#{s}/#{claims['iss']}" } ].each do |resolver|
      @options = { resolve: resolver }
      @_rack_test_sessions = nil
      signed

      assert_equal "usr_1/pk_test_client", @seen[Patchwork::Gateway::PRINCIPAL_KEY]
    end
  end

  # --- Gateway: information in 401 bodies ----------------------------------

  def test_401_bodies_do_not_echo_the_configured_audience_or_issuer
    wrong = JWT.encode({ iss: "key_evil", aud: [ "patchwork", "other-api" ], sub: "u", exp: Time.now.to_i + 60 }, TEST_RSA_KEY, "RS256")
    signed(token: wrong)

    assert_equal 401, last_response.status
    refute_includes last_response.body, "test-api"
    refute_includes last_response.body, "pk_test_client"
    assert_equal({ "error" => "invalid token" }, JSON.parse(last_response.body))
  end

  # --- Gateway: optional replay guard --------------------------------------

  def test_the_replay_guard_refuses_a_second_delivery_of_the_same_request
    seen = {}
    @options[:replay_guard] = ->(key, _ttl) { seen.key?(key) ? false : (seen[key] = true) }
    header "Patchwork-Signature", sign(path: "/tools/x", body: "{}")
    header "Authorization", "Bearer #{Patchwork::SessionToken.issue(subject: 'usr_1')}"

    post "/tools/x", "{}"
    assert_equal 200, last_response.status
    post "/tools/x", "{}"
    assert_equal 401, last_response.status
    assert_equal 1, @hits
  end

  # --- Gateway: relay mint (the mint-endpoint contract) --------------------

  def test_relay_mint_is_answered_with_a_bare_token_for_exactly_that_subject
    @options[:mint_path] = "/patchwork/mint"
    body = JSON.generate(subject: "usr_9f2:ws_acme")
    header "Patchwork-Signature", sign(path: "/patchwork/mint", body: body)
    post "/patchwork/mint", body

    assert_equal 201, last_response.status
    payload = JSON.parse(last_response.body)
    assert_equal %w[expires_in token], payload.keys.sort
    assert_equal "usr_9f2:ws_acme", Patchwork::SessionToken.verify(payload["token"])["sub"]
    assert_equal 0, @hits
  end

  def test_an_unsigned_mint_falls_through_to_the_apps_direct_branch
    @options[:mint_path] = "/patchwork/mint"
    post "/patchwork/mint", "{}"

    assert_equal 1, @hits
  end

  def test_relay_mint_refuses_bad_signatures_and_bad_subjects
    @options[:mint_path] = "/patchwork/mint"
    body = JSON.generate(subject: "usr_1")
    header "Patchwork-Signature", sign(path: "/patchwork/mint", body: body, secret: "wrong")
    post "/patchwork/mint", body
    assert_equal 401, last_response.status

    [ "{}", '{"subject":""}', '{"subject":["a"]}', '{"subject":"usr_1 "}', "[]", "nope" ].each do |bad|
      header "Patchwork-Signature", sign(path: "/patchwork/mint", body: bad)
      post "/patchwork/mint", bad
      assert_equal 400, last_response.status, "minted for #{bad}"
    end
  end

  def test_mint_relay_helper_for_apps_without_the_gateway
    body = JSON.generate(subject: "ticket:8821")
    result = Patchwork::Mint.relay(body: body, signature: sign(path: "/mint", body: body), path: "/mint")

    assert_equal "ticket:8821", Patchwork::SessionToken.verify(result[:token])["sub"]
    assert_raises(Patchwork::InvalidSignature) { Patchwork::Mint.relay(body: body, signature: sign(path: "/other", body: body), path: "/mint") }
  end

  # --- Health check --------------------------------------------------------

  def test_health_check_non_object_bodies_are_400_not_500
    [ "[1]", "null", "true", "42", '{"nonce":{"a":1}}', '{"nonce":""}', JSON.generate("nonce" => "n" * 300) ].each do |body|
      post Patchwork::HealthCheck::PATH, body
      assert_equal 400, last_response.status, "health check on #{body[0, 30]}"
      refute_includes last_response.body, body[0, 20] if body.size > 5
    end
  end

  def test_health_check_works_mounted_under_a_prefix
    @stack = ->(gateway) { Rack::URLMap.new("/tools" => gateway) }
    post "/tools/patchwork/up", JSON.generate("nonce" => "n0nce")

    assert_equal 200, last_response.status
    assert_equal Patchwork::HealthCheck.proof(secret: "whsec_current", nonce: "n0nce"), JSON.parse(last_response.body)["proof"]
    assert_equal 0, @hits
  end

  # --- Configuration and keys ----------------------------------------------

  def test_config_inspect_never_prints_secrets
    Patchwork.configure { |config| config.previous_request_secret = "whsec_previous" }
    [ Patchwork.config.inspect, Patchwork.config.to_s ].each do |text|
      refute_includes text, "PRIVATE"
      refute_includes text, Base64.strict_encode64(TEST_RSA_KEY.to_pem)[0, 40]
      refute_includes text, "whsec_current"
      refute_includes text, "whsec_previous"
      assert_includes text, "pk_test_client"
    end
  end

  def test_weak_public_and_non_rsa_keys_are_configuration_errors
    [ OpenSSL::PKey::RSA.generate(1024).to_pem,
      TEST_RSA_KEY.public_key.to_pem,
      OpenSSL::PKey::EC.generate("prime256v1").to_pem,
      TEST_RSA_KEY.export(OpenSSL::Cipher.new("aes-256-cbc"), "passphrase") ].each do |pem|
      configure_patchwork(signing_key: pem)
      assert_raises(Patchwork::ConfigurationError) { Patchwork::SessionToken.issue(subject: "u") }
    end
  end

  def test_whitespace_only_secrets_are_blank
    [ " ", "\n", "\t " ].each do |secret|
      assert_raises(Patchwork::ConfigurationError) do
        Patchwork::Webhook.verify(body: "{}", signature: sign(path: "/h", body: "{}", secret: "x"), secret: secret, path: "/h")
      end
    end
  end

  # --- Subjects ------------------------------------------------------------

  def test_a_multi_character_delimiter_cannot_make_two_tuples_collide
    format = Patchwork::Subject.define(:org, :user, delimiter: "::")

    # Both tuples used to encode to "acme:::mallory". Now only the one that
    # decodes back from that string is accepted, so encode is injective.
    victim = format.encode(org: "acme", user: ":mallory")
    assert_equal({ org: "acme", user: ":mallory" }, format.decode(victim).to_h)
    assert_raises(ArgumentError) { format.encode(org: "acme:", user: "mallory") }
    assert_equal "acme::mallory", format.encode(org: "acme", user: "mallory")
  end

  def test_whitespace_delimiters_are_refused
    [ " ", "\t", " | " ].each do |delimiter|
      assert_raises(ArgumentError) { Patchwork::Subject.define(:a, :b, delimiter: delimiter) }
    end
  end

  def test_part_names_cannot_shadow_struct_methods
    %i[freeze hash class to_h send object_id inspect].each do |name|
      assert_raises(ArgumentError, "allowed #{name}") { Patchwork::Subject.define(:user_id, name) }
    end
    assert_raises(ArgumentError) { Patchwork::Subject.define(:UserId) }
  end

  def test_unicode_whitespace_and_control_characters_are_refused
    format = Patchwork::Subject.define(:user_id, :workspace_id)
    [ "usr_1 ", "　usr_1", "usr_1​", "﻿usr_1", "usr_1\u0085", "usr\n1", "usr\r1", "usr\u00001" ].each do |value|
      assert_raises(ArgumentError, "minted #{value.inspect}") { Patchwork::Subject.validate!(value) }
      assert_raises(ArgumentError, "encoded #{value.inspect}") { format.encode(user_id: value, workspace_id: "ws") }
      assert_nil format.decode("#{value}:ws"), "decoded #{value.inspect}"
    end
  end

  def test_hostile_encodings_are_refused_not_raised
    format = Patchwork::Subject.define(:user_id, :workspace_id, prefix: "é")
    invalid = "usr_\xFF:ws".dup.force_encoding("UTF-8")
    binary = "usr_\xC3\xA9".b

    assert_nil format.decode(invalid)
    assert_raises(ArgumentError) { Patchwork::Subject.validate!(invalid) }
    assert_raises(ArgumentError) { format.encode(user_id: binary, workspace_id: "ws") }
    assert_equal "é:usr_1:ws", format.encode(user_id: "usr_1", workspace_id: "ws")
  end

  # --- Webhooks ------------------------------------------------------------

  def test_webhook_path_normalisation_accepts_fullpath_and_any_scheme_case
    body = JSON.generate("id" => "evt_1", "type" => "run.completed")
    signature = sign(path: "/hooks/patchwork", body: body, secret: "whsec_1")

    [ "/hooks/patchwork?x=1", "/hooks/patchwork#frag", "HTTPS://example.com/hooks/patchwork?a=b" ].each do |path|
      assert_equal "evt_1", Patchwork::Webhook.verify!(body: body, signature: signature, secret: "whsec_1", path: path).id
    end
    assert_raises(ArgumentError) { Patchwork::Webhook.verify(body: body, signature: signature, secret: "whsec_1", path: "http://[bad") }
  end

  def test_webhook_secret_and_secrets_together_is_an_error
    assert_raises(ArgumentError) do
      Patchwork::Webhook.verify!(body: "{}", signature: "t=1,v1=00", secret: "a", secrets: [ "b" ], path: "/h")
    end
  end

  def test_event_workspace_id_tolerates_a_non_object_context
    event = Patchwork::Webhook.parse(JSON.generate("context" => "workspace_id=ws_evil"))

    assert_nil event.workspace_id
  end
end

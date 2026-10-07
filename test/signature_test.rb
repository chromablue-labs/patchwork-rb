require "test_helper"

class SignatureTest < Minitest::Test
  include TestConfig

  DOCUMENT = JSON.parse(File.read(File.expand_path("vectors/signature.json", __dir__)), symbolize_names: true)
  VECTORS = DOCUMENT[:sign]
  VERDICTS = DOCUMENT[:verify]

  def test_the_file_is_the_scheme_this_module_implements
    assert_equal "patchwork-signature", DOCUMENT[:scheme]
    assert_equal Patchwork::Signature::SKEW, DOCUMENT[:skew_seconds]
    refute_empty VECTORS
    refute_empty VERDICTS
  end

  def test_reproduces_every_vector_byte_for_byte
    VECTORS.each do |vector|
      actual = Patchwork::Signature.sign(
        secret: vector[:secret], timestamp: vector[:timestamp],
        method: vector[:method], path: vector[:path], query: vector[:query],
        body: vector[:body], label: vector[:label]
      )
      assert_equal vector[:signature], actual,
        "diverged on #{vector[:label]} #{vector[:name]}"
    end
  end

  def test_reaches_every_expected_verdict
    VERDICTS.each do |vector|
      actual = Patchwork::Signature.verify(
        secrets: vector[:secrets], header: vector[:header],
        method: vector[:method], path: vector[:path], query: vector[:query],
        body: vector[:body], now: vector[:now]
      )
      assert_equal vector[:expect].to_sym, actual, "diverged on #{vector[:name]}"
    end
  end

  # Patchwork no longer sends v1, but a verifier still has to handle a header
  # that carries both — anything signed by an older platform, and the migration
  # these tests describe. Ask for both explicitly.
  def both_labels(query:, secret: "whsec_current", timestamp: Time.now.to_i)
    Patchwork::Signature.header(
      secrets: [ secret ], timestamp: timestamp, method: "GET",
      path: "/tools/orders", query: query, body: nil, labels: Patchwork::Signature::LABELS
    )
  end

  def verdict(header, query:, labels: Patchwork::Signature::LABELS)
    Patchwork::Signature.verify(
      secrets: [ "whsec_current" ], header: header, method: "GET",
      path: "/tools/orders", query: query, body: nil, labels: labels
    )
  end

  def test_requiring_v2_refuses_a_header_that_only_carries_v1
    header = both_labels(query: "status=open").sub(/,v2=\h{64}/, "")

    assert_equal :ok, verdict(header, query: "status=open")
    assert_equal :bad, verdict(header, query: "status=open", labels: [ Patchwork::Signature::V2 ])
  end

  def test_requiring_v2_still_refuses_a_query_that_changed
    header = both_labels(query: "status=open")

    assert_equal :ok, verdict(header, query: "status=open", labels: [ Patchwork::Signature::V2 ])
    assert_equal :bad, verdict(header, query: "status=closed", labels: [ Patchwork::Signature::V2 ])
  end

  # Without this, requiring v2 would be satisfied by the v1 value in the header.
  def test_requiring_v2_does_not_fall_back_to_v1_when_the_query_changed
    header = both_labels(query: "status=open")

    assert_equal :ok, verdict(header, query: "status=closed"),
      "the default accepts either label, and v1 does not cover the query"
    assert_equal :bad, verdict(header, query: "status=closed", labels: [ Patchwork::Signature::V2 ])
  end

  def test_header_emits_v2_and_not_the_retired_label
    header = Patchwork::Signature.header(
      secrets: [ "whsec_current" ], timestamp: Time.now.to_i, method: "POST", path: "/hooks", body: "{}"
    )

    assert_includes header, "v2="
    refute_includes header, "v1=", "v1 is retired; ask for it explicitly if a test needs one"
  end

  def test_header_can_still_produce_v1_on_request
    header = Patchwork::Signature.header(
      secrets: [ "whsec_current" ], timestamp: Time.now.to_i, method: "POST", path: "/hooks", body: "{}",
      labels: [ Patchwork::Signature::V1 ]
    )

    assert_includes header, "v1="
    refute_includes header, "v2="
  end

  def test_an_unknown_label_cannot_be_required
    assert_raises(ArgumentError) { verdict(both_labels(query: "a=1"), query: "a=1", labels: [ "v9" ]) }
  end

  def test_method_case_does_not_change_the_signature
    lower = VECTORS.find { |v| v[:method] == "post" }
    skip "no lowercase vector" if lower.nil?
    upper = VECTORS.find { |v| v[:method] == "POST" && v[:path] == lower[:path] && v[:body] == lower[:body] }

    assert_equal upper[:signature], lower[:signature]
  end

  def sign_header(secrets, body: "{}", timestamp: Time.now.to_i, path: "/hooks")
    Patchwork::Signature.header(secrets: secrets, timestamp: timestamp, method: "POST", path: path, body: body)
  end

  def verify(header, secrets:, body: "{}", path: "/hooks", now: Time.now.to_i)
    Patchwork::Signature.verify(secrets: secrets, header: header, method: "POST", path: path, body: body, now: now)
  end

  def test_verifies_a_signature_it_produced
    header = sign_header([ "s1" ])
    assert_equal :ok, verify(header, secrets: [ "s1" ])
  end

  def test_rejects_a_wrong_secret
    header = sign_header([ "s1" ])
    assert_equal :bad, verify(header, secrets: [ "s2" ])
  end

  def test_rejects_a_tampered_body
    header = sign_header([ "s1" ], body: '{"amount":1}')
    assert_equal :bad, verify(header, secrets: [ "s1" ], body: '{"amount":9999}')
  end

  def test_rejects_a_tampered_path
    header = sign_header([ "s1" ], path: "/hooks")
    assert_equal :bad, verify(header, secrets: [ "s1" ], path: "/admin")
  end

  def test_during_rotation_both_secrets_verify
    header = sign_header([ "new", "old" ])

    assert_equal :ok, verify(header, secrets: [ "new" ])
    assert_equal :ok, verify(header, secrets: [ "old" ])
    assert_equal :ok, verify(header, secrets: [ "new", "old" ])
  end

  def test_a_rotation_header_carries_every_value_not_just_the_last
    header = sign_header([ "new", "old" ])

    assert_equal 2, header.scan("v2=").size
    assert_equal :ok, verify(header, secrets: [ "new" ]),
      "parsing the header into a Hash keeps only the last value and silently breaks the rotation overlap"
  end

  def test_rejects_when_neither_rotation_secret_matches
    header = sign_header([ "new", "old" ])
    assert_equal :bad, verify(header, secrets: [ "unrelated" ])
  end

  def test_stale_outside_the_skew_window_in_both_directions
    now = 1_759_000_000

    past = sign_header([ "s1" ], timestamp: now - 301)
    future = sign_header([ "s1" ], timestamp: now + 301)

    assert_equal :stale, verify(past, secrets: [ "s1" ], now: now)
    assert_equal :stale, verify(future, secrets: [ "s1" ], now: now)
  end

  def test_inside_the_skew_window_verifies
    now = 1_759_000_000
    header = sign_header([ "s1" ], timestamp: now - 299)

    assert_equal :ok, verify(header, secrets: [ "s1" ], now: now)
  end

  def test_a_missing_or_garbage_header_never_returns_ok
    [ nil, "", "garbage", "t=,v1=", "v1=abc" ].each do |header|
      refute_equal :ok, verify(header, secrets: [ "s1" ]), "accepted #{header.inspect}"
    end
  end

  def test_a_signature_of_the_wrong_length_is_rejected_without_raising
    header = "t=#{Time.now.to_i},v1=short"
    assert_equal :bad, verify(header, secrets: [ "s1" ])
  end

  def test_verify_bang_raises_the_typed_errors
    now = 1_759_000_000

    assert_raises(Patchwork::StaleSignature) do
      Patchwork::Signature.verify!(secrets: [ "s1" ], header: sign_header([ "s1" ], timestamp: now - 900),
        method: "POST", path: "/hooks", body: "{}", now: now)
    end

    assert_raises(Patchwork::InvalidSignature) do
      Patchwork::Signature.verify!(secrets: [ "nope" ], header: sign_header([ "s1" ]),
        method: "POST", path: "/hooks", body: "{}")
    end
  end

  def test_a_missing_or_empty_secret_raises_instead_of_verifying
    header = sign_header([ "s1" ])

    [ [], [ nil ], [ "" ], nil, "" ].each do |secrets|
      assert_raises(Patchwork::ConfigurationError, "verified with #{secrets.inspect}") { verify(header, secrets: secrets) }
    end
  end

  def test_an_empty_secret_cannot_be_used_to_forge
    forged = "t=#{Time.now.to_i},v1=#{OpenSSL::HMAC.hexdigest('SHA256', '', "#{Time.now.to_i}.POST./hooks.#{Base64.strict_encode64(OpenSSL::Digest::SHA256.digest('{}'))}")}"

    assert_raises(Patchwork::ConfigurationError) { verify(forged, secrets: [ "" ]) }
    assert_raises(Patchwork::ConfigurationError) do
      Patchwork::Signature.sign(secret: "", timestamp: Time.now.to_i, method: "POST", path: "/hooks", body: "{}")
    end
  end
end

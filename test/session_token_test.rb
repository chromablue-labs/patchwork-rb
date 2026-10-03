require "test_helper"

class SessionTokenTest < Minitest::Test
  include TestConfig

  def setup
    configure_patchwork
  end

  def claims_of(token)
    JWT.decode(token, nil, false).first
  end

  def test_issues_a_token_the_platform_contract_expects
    token = Patchwork::SessionToken.issue(subject: "user-1:tenant-1")
    claims = claims_of(token)

    assert_equal "pk_test_client", claims["iss"]
    assert_includes claims["aud"], "patchwork"
    assert_includes claims["aud"], "test-api"
    assert_equal "user-1:tenant-1", claims["sub"]
    assert claims["exp"] > claims["iat"]
    refute_nil claims["jti"]
  end

  def test_carries_the_kid_so_jwks_rotation_can_work
    token = Patchwork::SessionToken.issue(subject: "u:t")
    _, header = JWT.decode(token, nil, false)

    assert_equal "test-kid", header["kid"]
    assert_equal "RS256", header["alg"]
  end

  def test_each_token_has_a_distinct_jti
    first = claims_of(Patchwork::SessionToken.issue(subject: "u:t"))
    second = claims_of(Patchwork::SessionToken.issue(subject: "u:t"))

    refute_equal first["jti"], second["jti"]
  end

  def test_includes_the_connection_claim_when_given
    claims = claims_of(Patchwork::SessionToken.issue(subject: "u:t", connection_id: "conn_123"))
    assert_equal "conn_123", claims["conn"]
  end

  def test_omits_the_connection_claim_when_absent
    refute claims_of(Patchwork::SessionToken.issue(subject: "u:t")).key?("conn")
  end

  def test_refuses_a_wildcard_connection
    assert_raises(ArgumentError) do
      Patchwork::SessionToken.issue(subject: "u:t", connection_id: "*")
    end
  end

  def test_round_trips_its_own_token
    token = Patchwork::SessionToken.issue(subject: "u:t")
    assert_equal "u:t", Patchwork::SessionToken.verify(token)["sub"]
  end

  def test_rejects_an_hs256_token_signed_with_the_public_key
    forged = JWT.encode(
      { iss: "pk_test_client", aud: [ "patchwork", "test-api" ], sub: "attacker:tenant-1",
        exp: Time.now.to_i + 300 },
      TEST_RSA_KEY.public_key.to_pem,
      "HS256"
    )

    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(forged) }
  end

  def test_rejects_an_unsigned_token
    forged = JWT.encode({ sub: "attacker:tenant-1", exp: Time.now.to_i + 300 }, nil, "none")
    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(forged) }
  end

  def test_rejects_a_token_signed_by_another_key
    other = OpenSSL::PKey::RSA.generate(2048)
    forged = JWT.encode(
      { iss: "pk_test_client", aud: [ "patchwork", "test-api" ], sub: "u:t", exp: Time.now.to_i + 300 },
      other, "RS256"
    )

    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(forged) }
  end

  def test_rejects_an_expired_token
    token = Patchwork::SessionToken.issue(subject: "u:t", ttl: -60)
    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(token) }
  end

  def test_rejects_a_token_for_another_audience
    wrong = JWT.encode(
      { iss: "pk_test_client", aud: [ "somebody-else" ], sub: "u:t", exp: Time.now.to_i + 300 },
      TEST_RSA_KEY, "RS256"
    )

    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(wrong) }
  end

  def test_rejects_a_token_missing_required_claims
    bare = JWT.encode({ aud: "test-api", exp: Time.now.to_i + 300 }, TEST_RSA_KEY, "RS256")
    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(bare) }
  end

  def test_raises_a_configuration_error_without_an_issuer
    Patchwork.configure { |config| config.issuer = nil }
    assert_raises(Patchwork::ConfigurationError) { Patchwork::SessionToken.issue(subject: "u:t") }
  end

  def test_accepts_a_raw_pem_signing_key_as_well_as_base64
    Patchwork.configure { |config| config.signing_key = TEST_RSA_KEY.to_pem }
    assert Patchwork::SessionToken.issue(subject: "u:t")
  end

  def test_publishes_a_jwks_with_public_material_only
    jwk = Patchwork::SigningKey.public_jwk

    assert_equal "test-kid", jwk[:kid] || jwk["kid"]
    serialized = JSON.generate(jwk)
    refute_includes serialized, "\"d\"", "private exponent leaked into the JWKS"
    refute_includes serialized, "PRIVATE"
  end

  def test_the_subject_is_opaque_any_shape_round_trips
    [ "usr_1", "usr_1:ws_acme", "slack:T04AB:U0APP", "ticket:8821", "job:nightly-recon", "a|b|c" ].each do |subject|
      token = Patchwork::SessionToken.issue(subject: subject)
      assert_equal subject, Patchwork::SessionToken.verify(token)["sub"]
    end
  end

  def test_refuses_to_mint_an_empty_or_padded_subject
    [ nil, "", "usr_1 ", " usr_1", 42 ].each do |subject|
      assert_raises(ArgumentError, "minted #{subject.inspect}") { Patchwork::SessionToken.issue(subject: subject) }
    end
  end

  def test_rejects_a_token_with_an_empty_subject
    blank = JWT.encode(
      { iss: "pk_test_client", aud: [ "patchwork", "test-api" ], sub: "", exp: Time.now.to_i + 300 },
      TEST_RSA_KEY, "RS256"
    )

    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(blank) }
  end

  def test_rejects_a_token_from_another_issuer
    other = JWT.encode(
      { iss: "key_someone_else", aud: [ "patchwork", "test-api" ], sub: "u", exp: Time.now.to_i + 300 },
      TEST_RSA_KEY, "RS256"
    )

    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(other) }
  end

  def test_audience_has_no_default
    Patchwork.configure { |config| config.audience = nil }

    assert_raises(Patchwork::ConfigurationError) { Patchwork::SessionToken.issue(subject: "u") }
  end

  def test_kid_defaults_to_the_key_thumbprint_and_rotates_with_the_key
    configure_patchwork(signing_kid: nil)
    first = Patchwork::SigningKey.kid

    configure_patchwork(signing_kid: nil, signing_key: OpenSSL::PKey::RSA.generate(2048).to_pem)
    second = Patchwork::SigningKey.kid

    assert_match(/\A[A-Za-z0-9_-]{43}\z/, first)
    refute_equal first, second, "a new key must not reuse the old key's kid"
  end

  def test_rejects_a_token_whose_lifetime_exceeds_the_bound
    now = Time.now.to_i
    token = JWT.encode(
      { iss: "pk_test_client", aud: [ "patchwork", "test-api" ], sub: "usr_1:ws_acme",
        iat: now, exp: now + 86_400 },
      TEST_RSA_KEY,
      "RS256"
    )

    error = assert_raises(Patchwork::LifetimeExceeded) { Patchwork::SessionToken.verify(token) }
    assert_match(/exceeds the 900s bound/, error.message)
  end

  def test_a_lifetime_failure_is_still_an_invalid_token_to_anything_catching_that
    now = Time.now.to_i
    token = JWT.encode(
      { iss: "pk_test_client", aud: [ "patchwork", "test-api" ], sub: "usr_1:ws_acme",
        iat: now, exp: now + 86_400 },
      TEST_RSA_KEY,
      "RS256"
    )

    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(token) }
  end

  def test_requires_iat_so_a_lifetime_can_be_bounded_at_all
    token = JWT.encode(
      { iss: "pk_test_client", aud: [ "patchwork", "test-api" ], sub: "usr_1:ws_acme",
        exp: Time.now.to_i + 120 },
      TEST_RSA_KEY,
      "RS256"
    )

    assert_raises(Patchwork::InvalidToken) { Patchwork::SessionToken.verify(token) }
  end

  def test_a_consumer_can_raise_the_bound_it_accepts
    configure_patchwork(max_token_lifetime: 86_400)
    token = Patchwork::SessionToken.issue(subject: "usr_1:ws_acme", ttl: 3_600)

    assert_equal "usr_1:ws_acme", Patchwork::SessionToken.verify(token)["sub"]
  end

  def test_a_nil_bound_turns_the_check_off
    configure_patchwork(max_token_lifetime: nil)
    token = Patchwork::SessionToken.issue(subject: "usr_1:ws_acme", ttl: 86_400)

    assert_equal "usr_1:ws_acme", Patchwork::SessionToken.verify(token)["sub"]
  end
end

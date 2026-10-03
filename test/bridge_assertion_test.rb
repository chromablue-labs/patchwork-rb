require "test_helper"

class BridgeAssertionTest < Minitest::Test
  include TestConfig

  CALLBACK = "https://api.usepatchwork.co/v1/mcp/callback".freeze

  def setup
    configure_patchwork
  end

  def issue(**overrides)
    Patchwork::BridgeAssertion.issue(
      **{ subject: "usr_1:ws_acme", nonce: "state-abc", audience: CALLBACK }.merge(overrides)
    )
  end

  def test_issues_the_assertion_the_callback_expects
    claims = JWT.decode(issue, nil, false).first

    assert_equal "usr_1:ws_acme", claims["sub"]
    assert_equal CALLBACK, claims["aud"]
    assert_equal "state-abc", claims["nonce"]
    assert_equal 120, claims["exp"] - claims["iat"]
  end

  def test_carries_the_kid_so_the_callback_can_pick_the_key
    _, header = JWT.decode(issue, nil, false)

    assert_equal "test-kid", header["kid"]
    assert_equal "RS256", header["alg"]
  end

  def test_refuses_a_lifetime_longer_than_the_callback_allows
    assert_raises(ArgumentError) { issue(ttl: 121) }
  end

  def test_refuses_to_mint_without_a_nonce_or_audience
    assert_raises(ArgumentError) { issue(nonce: "") }
    assert_raises(ArgumentError) { issue(audience: "") }
  end

  def test_holds_the_subject_to_the_same_rules_as_a_session_token
    assert_raises(ArgumentError) { issue(subject: "") }
    assert_raises(ArgumentError) { issue(subject: " usr_1") }
    assert_raises(ArgumentError) { issue(subject: "usr\n1") }
  end

  def test_round_trips_its_own_assertion
    claims = Patchwork::BridgeAssertion.verify(issue, audience: CALLBACK, nonce: "state-abc")

    assert_equal "usr_1:ws_acme", claims["sub"]
  end

  def test_rejects_a_nonce_from_another_flow
    assert_raises(Patchwork::InvalidToken) do
      Patchwork::BridgeAssertion.verify(issue, audience: CALLBACK, nonce: "state-xyz")
    end
  end

  def test_rejects_an_assertion_aimed_at_another_callback
    assert_raises(Patchwork::InvalidToken) do
      Patchwork::BridgeAssertion.verify(issue, audience: "https://evil.example/cb", nonce: "state-abc")
    end
  end

  def test_rejects_an_hs256_assertion_signed_with_the_public_key
    now = Time.now.to_i
    forged = JWT.encode(
      { sub: "attacker:ws_acme", aud: CALLBACK, nonce: "state-abc", iat: now, exp: now + 120 },
      TEST_RSA_KEY.public_key.to_pem,
      "HS256"
    )

    assert_raises(Patchwork::InvalidToken) do
      Patchwork::BridgeAssertion.verify(forged, audience: CALLBACK, nonce: "state-abc")
    end
  end

  def test_rejects_an_unsigned_assertion
    now = Time.now.to_i
    forged = JWT.encode(
      { sub: "attacker:ws_acme", aud: CALLBACK, nonce: "state-abc", iat: now, exp: now + 120 },
      nil,
      "none"
    )

    assert_raises(Patchwork::InvalidToken) do
      Patchwork::BridgeAssertion.verify(forged, audience: CALLBACK, nonce: "state-abc")
    end
  end

  def test_rejects_an_expired_assertion
    stale = JWT.encode(
      { sub: "usr_1:ws_acme", aud: CALLBACK, nonce: "state-abc",
        iat: Time.now.to_i - 600, exp: Time.now.to_i - 300 },
      TEST_RSA_KEY,
      "RS256"
    )

    assert_raises(Patchwork::InvalidToken) do
      Patchwork::BridgeAssertion.verify(stale, audience: CALLBACK, nonce: "state-abc")
    end
  end

  def test_rejects_an_assertion_with_no_nonce_claim
    now = Time.now.to_i
    token = JWT.encode(
      { sub: "usr_1:ws_acme", aud: CALLBACK, iat: now, exp: now + 120 },
      TEST_RSA_KEY,
      "RS256"
    )

    assert_raises(Patchwork::InvalidToken) do
      Patchwork::BridgeAssertion.verify(token, audience: CALLBACK, nonce: "state-abc")
    end
  end

  def test_verification_demands_an_expected_nonce
    assert_raises(ArgumentError) do
      Patchwork::BridgeAssertion.verify(issue, audience: CALLBACK, nonce: "")
    end
  end
end

require "test_helper"

class HealthCheckTest < Minitest::Test
  include TestConfig

  def setup
    configure_patchwork
  end

  def test_returns_a_proof_only_the_shared_secret_can_produce
    response = Patchwork::HealthCheck.respond(body: JSON.generate("nonce" => "abc123"))

    assert_equal "abc123", response[:nonce]
    assert_equal OpenSSL::HMAC.hexdigest("SHA256", "whsec_current", "patchwork-up.v1:abc123"), response[:proof]
  end

  def test_a_different_secret_produces_a_different_proof
    mine = Patchwork::HealthCheck.proof(secret: "whsec_current", nonce: "abc123")
    theirs = Patchwork::HealthCheck.proof(secret: "whsec_other", nonce: "abc123")

    refute_equal mine, theirs
  end

  def test_rejects_a_body_with_no_nonce
    assert_raises(Patchwork::Error) { Patchwork::HealthCheck.respond(body: JSON.generate("hello" => "world")) }
  end

  def test_rejects_a_non_json_body
    assert_raises(Patchwork::Error) { Patchwork::HealthCheck.respond(body: "nope") }
  end

  def test_raises_when_no_request_secret_is_configured
    Patchwork.configure { |config| config.request_secret = nil }

    assert_raises(Patchwork::ConfigurationError) do
      Patchwork::HealthCheck.respond(body: JSON.generate("nonce" => "abc"))
    end
  end
end

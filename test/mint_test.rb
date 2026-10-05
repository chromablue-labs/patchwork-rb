require "test_helper"

class MintTest < Minitest::Test
  include TestConfig

  PATH = "/patchwork/mint".freeze

  def setup
    configure_patchwork
  end

  def signed(body, secret: "whsec_current", path: PATH)
    Patchwork::Signature.header(
      secrets: [ secret ], timestamp: Time.now.to_i, method: "POST", path: path, body: body
    )
  end

  def relay(subject: "usr_1:ws_1", secret: "whsec_current", **options)
    body = JSON.generate("subject" => subject)
    Patchwork::Mint.relay(body: body, signature: signed(body, secret: secret), path: PATH, **options)
  end

  def claims(result)
    JWT.decode(result[:token], TEST_RSA_KEY.public_key, true, algorithms: [ "RS256" ]).first
  end

  def test_mints_for_the_subject_in_the_body
    result = relay

    assert_equal "usr_1:ws_1", claims(result)["sub"]
    assert_equal Patchwork.config.token_ttl, result[:expires_in]
  end

  def test_stamps_conn_from_the_configured_connection
    configure_patchwork(connection_id: "conn-abc")

    assert_equal "conn-abc", claims(relay)["conn"]
  end

  def test_an_explicit_connection_id_overrides_the_configured_one
    configure_patchwork(connection_id: "conn-abc")

    assert_equal "conn-xyz", claims(relay(connection_id: "conn-xyz"))["conn"]
  end

  def test_omits_conn_when_no_connection_is_configured
    assert_nil claims(relay)["conn"]
  end

  def test_refuses_a_signature_from_another_secret
    assert_raises(Patchwork::InvalidSignature) { relay(secret: "whsec_other") }
  end

  def test_refuses_a_body_with_no_usable_subject
    body = JSON.generate("subject" => "")

    assert_raises(Patchwork::Mint::BadRequest) do
      Patchwork::Mint.relay(body: body, signature: signed(body), path: PATH)
    end
  end

  def test_refuses_a_body_over_the_cap
    body = JSON.generate("subject" => "u", "pad" => "x" * (16 * 1024))

    assert_raises(Patchwork::Mint::BadRequest) do
      Patchwork::Mint.relay(body: body, signature: signed(body), path: PATH)
    end
  end
end

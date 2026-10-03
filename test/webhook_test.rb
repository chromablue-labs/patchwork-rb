require "test_helper"

class WebhookTest < Minitest::Test
  include TestConfig

  BODY = JSON.generate(
    "id" => "evt_abc", "type" => "run.completed", "created_at" => "2026-09-28T12:00:00Z",
    "origin" => "agent", "source" => { "kind" => "run", "id" => "run_1" },
    "context" => { "workspace_id" => "ws_1", "connection_id" => "conn_1" },
    "run_id" => "run_1", "thread_id" => "thr_1", "data" => { "state" => "closed" }
  )

  def header(secrets, timestamp: Time.now.to_i, body: BODY, path: "/hooks/patchwork")
    Patchwork::Signature.header(secrets: secrets, timestamp: timestamp, method: "POST", path: path, body: body)
  end

  def test_verifies_and_parses_a_delivery
    event = Patchwork::Webhook.verify!(
      body: BODY, signature: header([ "whsec_1" ]), secret: "whsec_1", path: "/hooks/patchwork"
    )

    assert_equal "evt_abc", event.id
    assert_equal "run.completed", event.type
    assert_equal "agent", event.origin
    assert_equal "run_1", event.run_id
    assert_equal "thr_1", event.thread_id
    assert_equal "ws_1", event.workspace_id
    assert_equal "closed", event.data["state"]
    refute event.test?
  end

  def test_accepts_a_full_url_as_the_path
    signature = header([ "whsec_1" ], path: "/hooks/patchwork")

    event = Patchwork::Webhook.verify!(
      body: BODY, signature: signature, secret: "whsec_1",
      path: "https://example.com/hooks/patchwork"
    )

    assert_equal "evt_abc", event.id
  end

  def test_a_root_endpoint_signs_as_slash
    signature = header([ "whsec_1" ], path: "/")

    assert Patchwork::Webhook.verify!(
      body: BODY, signature: signature, secret: "whsec_1", path: "https://example.com"
    )
  end

  def test_rejects_a_tampered_body
    signature = header([ "whsec_1" ])
    tampered = BODY.sub("closed", "opened")

    assert_raises(Patchwork::InvalidSignature) do
      Patchwork::Webhook.verify!(body: tampered, signature: signature, secret: "whsec_1", path: "/hooks/patchwork")
    end
  end

  def test_rejects_the_wrong_secret
    assert_raises(Patchwork::InvalidSignature) do
      Patchwork::Webhook.verify!(
        body: BODY, signature: header([ "whsec_1" ]), secret: "whsec_other", path: "/hooks/patchwork"
      )
    end
  end

  def test_rejects_a_replay_outside_the_window
    now = 1_759_000_000
    signature = header([ "whsec_1" ], timestamp: now - 3600)

    assert_raises(Patchwork::StaleSignature) do
      Patchwork::Webhook.verify!(
        body: BODY, signature: signature, secret: "whsec_1", path: "/hooks/patchwork", now: now
      )
    end
  end

  def test_verifies_across_a_secret_rotation
    signature = header([ "whsec_new", "whsec_old" ])

    assert Patchwork::Webhook.verify!(
      body: BODY, signature: signature, secrets: [ "whsec_new" ], path: "/hooks/patchwork"
    )
    assert Patchwork::Webhook.verify!(
      body: BODY, signature: signature, secrets: [ "whsec_old" ], path: "/hooks/patchwork"
    )
  end

  def test_non_raising_verify_returns_nil_on_a_bad_signature
    assert_nil Patchwork::Webhook.verify(
      body: BODY, signature: header([ "whsec_1" ]), secret: "nope", path: "/hooks/patchwork"
    )
  end

  def test_recognises_a_test_delivery
    body = JSON.generate("id" => "evt_t", "type" => "endpoint.test", "data" => {})
    signature = header([ "whsec_1" ], body: body)

    event = Patchwork::Webhook.verify!(
      body: body, signature: signature, secret: "whsec_1", path: "/hooks/patchwork"
    )

    assert event.test?
  end

  def test_a_non_json_body_that_passes_the_signature_still_raises
    body = "not json"
    signature = header([ "whsec_1" ], body: body)

    assert_raises(Patchwork::Error) do
      Patchwork::Webhook.verify!(body: body, signature: signature, secret: "whsec_1", path: "/hooks/patchwork")
    end
  end

  def test_an_empty_webhook_secret_raises_rather_than_accepting_a_forgery
    forged = header([ "x" ]).sub(/v1=\h+/, "v1=#{OpenSSL::HMAC.hexdigest('SHA256', '', 'anything')}")

    [ "", nil ].each do |secret|
      assert_raises(Patchwork::ConfigurationError) do
        Patchwork::Webhook.verify(body: BODY, signature: forged, secret: secret, path: "/hooks/patchwork")
      end
    end
  end

  def test_a_non_object_body_is_an_error
    body = "[1,2]"
    assert_raises(Patchwork::Error) do
      Patchwork::Webhook.verify!(body: body, signature: header([ "whsec_1" ], body: body), secret: "whsec_1", path: "/hooks/patchwork")
    end
  end
end

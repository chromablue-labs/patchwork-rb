require "test_helper"
require "patchwork/rails"

class RailsPresentedTest < Minitest::Test
  include TestConfig

  Membership = Patchwork::Subject.define(:user_id, :workspace_id)

  FakeRequest = Struct.new(:request_method, :path, :raw_post, :headers, :env, :query_string, keyword_init: true) do
    def query_string = self[:query_string].to_s
  end

  class FakeController
    def self.before_action(*names)
      registered.concat(names)
    end

    def self.registered
      @registered ||= []
    end

    attr_accessor :request
    attr_reader :rendered

    def render(**payload)
      @rendered = payload
    end
  end

  class ToolsController < FakeController
    include Patchwork::Rails::Presented

    MEMBERS = { "usr_1" => "ws_acme" }.freeze

    private

    def patchwork_resolve(subject)
      MEMBERS[subject.user_id] == subject.workspace_id ? { user: subject.user_id } : nil
    end
  end

  class ClaimsController < FakeController
    include Patchwork::Rails::Presented

    private

    def patchwork_resolve(subject, claims)
      { subject: subject, issuer: claims["iss"] }
    end
  end

  class ForgetfulController < FakeController
    include Patchwork::Rails::Presented
  end

  def setup
    configure_patchwork
    ToolsController.instance_variable_set(:@patchwork_subject_format, Membership)
  end

  def request_for(path: "/api/tools/lookup", body: '{"q":1}', subject: "usr_1:ws_acme",
                  secret: "whsec_current", token: :valid, timestamp: Time.now.to_i, env: {})
    bearer = token == :valid ? Patchwork::SessionToken.issue(subject: subject) : token
    signature = Patchwork::Signature.header(
      secrets: [ secret ], timestamp: timestamp, method: "POST", path: path, body: body
    )

    FakeRequest.new(
      request_method: "POST",
      path: path,
      raw_post: body,
      headers: { "Patchwork-Signature" => signature, "Authorization" => bearer && "Bearer #{bearer}" },
      env: env
    )
  end

  def call(controller_class = ToolsController, **options)
    controller = controller_class.new
    controller.request = request_for(**options)
    controller.send(:verify_patchwork_call!)
    controller
  end

  def test_the_concern_registers_the_before_action
    assert_includes ToolsController.registered, :verify_patchwork_call!
  end

  def test_a_valid_call_resolves_a_principal_and_renders_nothing
    controller = call

    assert_nil controller.rendered
    assert_equal "usr_1:ws_acme", controller.send(:patchwork_subject)
    assert_equal({ user: "usr_1" }, controller.send(:patchwork_principal))
    assert_equal "pk_test_client", controller.send(:patchwork_claims)["iss"]
  end

  def test_a_resolver_that_wants_the_claims_gets_them
    ClaimsController.instance_variable_set(:@patchwork_subject_format, nil)
    controller = call(ClaimsController)

    assert_equal "pk_test_client", controller.send(:patchwork_principal)[:issuer]
    assert_equal "usr_1:ws_acme", controller.send(:patchwork_principal)[:subject]
  end

  def test_a_refused_principal_is_401
    controller = call(subject: "usr_1:ws_other")

    assert_equal :unauthorized, controller.rendered[:status]
    assert_nil controller.send(:patchwork_subject)
  end

  def test_a_subject_outside_the_declared_format_is_401
    controller = call(subject: "usr_1")

    assert_equal :unauthorized, controller.rendered[:status]
  end

  def test_a_bad_signature_is_401
    controller = call(secret: "wrong-secret")

    assert_equal :unauthorized, controller.rendered[:status]
    assert_equal "invalid signature", controller.rendered[:json][:error]
  end

  def test_a_stale_signature_says_so
    controller = call(timestamp: Time.now.to_i - 4_000)

    assert_equal "stale signature", controller.rendered[:json][:error]
  end

  def test_a_missing_signature_is_401_rather_than_falling_through
    controller = ToolsController.new
    controller.request = request_for
    controller.request.headers["Patchwork-Signature"] = ""
    controller.send(:verify_patchwork_call!)

    assert_equal :unauthorized, controller.rendered[:status]
  end

  def test_a_forged_or_missing_token_is_401
    assert_equal :unauthorized, call(token: "not-a-token").rendered[:status]
    assert_equal :unauthorized, call(token: nil).rendered[:status]
  end

  def test_a_method_override_on_a_signed_request_is_refused
    controller = call(env: { "HTTP_X_HTTP_METHOD_OVERRIDE" => "DELETE" })

    assert_equal "invalid signature", controller.rendered[:json][:error]
  end

  def test_the_401_never_leaks_key_material
    controller = call(secret: "wrong-secret")

    refute_includes controller.rendered[:json][:error], "whsec_current"
    refute_includes controller.rendered[:json][:error], "PRIVATE"
  end

  def test_a_controller_that_forgets_the_resolver_fails_loudly
    error = assert_raises(Patchwork::ConfigurationError) { call(ForgetfulController) }

    assert_match(/patchwork_resolve/, error.message)
  end
end

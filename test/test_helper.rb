require "minitest/autorun"
require "json"
require "patchwork"

TEST_RSA_KEY = OpenSSL::PKey::RSA.generate(2048).freeze

module TestConfig
  def configure_patchwork(**overrides)
    Patchwork.reset!
    Patchwork.configure do |config|
      config.signing_key = Base64.strict_encode64(TEST_RSA_KEY.to_pem)
      config.signing_kid = "test-kid"
      config.issuer = "pk_test_client"
      config.audience = "test-api"
      config.request_secret = "whsec_current"
      config.previous_request_secret = nil
      overrides.each { |key, value| config.public_send("#{key}=", value) }
    end
  end

  def teardown
    Patchwork.reset!
    super
  end
end

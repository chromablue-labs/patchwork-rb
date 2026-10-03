require "json"
require "openssl"

module Patchwork
  module HealthCheck
    PATH = "/patchwork/up".freeze
    PROOF_CONTEXT = "patchwork-up.v1:".freeze
    MAX_NONCE_BYTES = 256

    BadRequest = Class.new(Error)

    # The context prefix keeps this proof from ever equalling a request
    # signature, whose payload starts with a numeric timestamp — so answering
    # unsigned probes is not a signing oracle.
    def self.proof(secret:, nonce:)
      key = secret.to_s
      raise ConfigurationError, "request_secret is not set" if key.strip.empty?

      OpenSSL::HMAC.hexdigest("SHA256", key, "#{PROOF_CONTEXT}#{nonce}")
    end

    def self.respond(body:, secret: nil)
      parsed = JSON.parse(body.to_s)
      raise BadRequest, "health check body must be a JSON object" unless parsed.is_a?(Hash)

      nonce = parsed["nonce"]
      unless nonce.is_a?(String) && !nonce.empty? && nonce.bytesize <= MAX_NONCE_BYTES
        raise BadRequest, "health check nonce must be a string of 1-#{MAX_NONCE_BYTES} bytes"
      end

      { nonce: nonce, proof: proof(secret: secret || Patchwork.config.request_secret, nonce: nonce) }
    rescue JSON::ParserError
      raise BadRequest, "health check body is not JSON"
    end
  end
end

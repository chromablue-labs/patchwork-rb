module Patchwork
  class Configuration
    # signing_key  — your RSA private key, PEM or base64-encoded PEM.
    # signing_kid  — the JWKS key id. Defaults to the key's RFC 7638 thumbprint,
    #                so rotating the key rotates the kid with it.
    # issuer       — your Patchwork API key's public id (key_…).
    # audience     — your own API's audience. Minted tokens carry it next to
    #                "patchwork", and tool calls are verified against it.
    # request_secret / previous_request_secret — the connection's shared secret,
    #                and the one it replaced while a rotation is in flight.
    attr_accessor :signing_key, :signing_kid, :issuer, :audience,
                  :request_secret, :previous_request_secret, :token_ttl,
                  :max_token_lifetime, :connection_id

    DEFAULT_TTL = 120
    DEFAULT_MAX_TOKEN_LIFETIME = 900

    def initialize
      @token_ttl = DEFAULT_TTL
      @max_token_lifetime = DEFAULT_MAX_TOKEN_LIFETIME
    end

    def request_secrets
      [ request_secret, previous_request_secret ].map(&:to_s).reject(&:empty?)
    end

    def signing_key?
      !signing_key.to_s.empty?
    end

    def request_secret?
      !request_secrets.empty?
    end

    def issuer!
      fetch!(:issuer)
    end

    def audience!
      fetch!(:audience)
    end

    SECRETS = %i[signing_key request_secret previous_request_secret].freeze

    # Default #inspect prints every ivar, so a config that reaches a log line,
    # an error tracker or a console would carry the private key with it.
    def inspect
      fields = %i[issuer audience signing_kid connection_id token_ttl max_token_lifetime].map { |name| "#{name}=#{public_send(name).inspect}" }
      fields += SECRETS.map { |name| "#{name}=#{public_send(name).to_s.empty? ? 'nil' : '[REDACTED]'}" }
      "#<Patchwork::Configuration #{fields.join(', ')}>"
    end
    alias to_s inspect

    private

    def fetch!(name)
      value = public_send(name).to_s
      raise ConfigurationError, "#{name} is not set — see Patchwork.configure" if value.empty?

      value
    end
  end
end

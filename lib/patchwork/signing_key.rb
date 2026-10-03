require "base64"
require "openssl"
require "jwt"

module Patchwork
  module SigningKey
    ALG = "RS256".freeze
    MIN_BITS = 2048

    def self.configured?
      Patchwork.config.signing_key?
    end

    def self.private_key
      @private_key ||= begin
        material = Patchwork.config.signing_key
        raise ConfigurationError, "signing_key is not set" if material.to_s.empty?

        key = parse(decode(material))
        raise ConfigurationError, "signing_key must be an RSA private key, not a public key" unless key.private?
        raise ConfigurationError, "signing_key must be at least #{MIN_BITS} bits" if key.n.num_bits < MIN_BITS

        key
      end
    end

    def self.public_key
      private_key.public_key
    end

    def self.kid
      configured = Patchwork.config.signing_kid.to_s
      return configured unless configured.empty?

      @thumbprint ||= JWT::JWK.new(public_key, kid_generator: JWT::JWK::Thumbprint).kid
    end

    def self.public_jwk
      JWT::JWK.new(public_key, kid: kid).export
    end

    def self.jwks
      { keys: [ public_jwk ] }
    end

    def self.reset!
      @private_key = nil
      @thumbprint = nil
    end

    def self.parse(pem)
      # An explicit empty passphrase: an encrypted key fails here instead of
      # blocking on an interactive prompt at boot.
      OpenSSL::PKey::RSA.new(pem, "")
    rescue OpenSSL::PKey::PKeyError
      raise ConfigurationError, "signing_key is not an RSA private key (an EC or encrypted key is not supported)"
    end
    private_class_method :parse

    def self.decode(material)
      return material if material.include?("-----BEGIN")

      Base64.strict_decode64(material)
    rescue ArgumentError
      raise ConfigurationError, "signing_key is neither PEM nor base64-encoded PEM"
    end
    private_class_method :decode
  end
end

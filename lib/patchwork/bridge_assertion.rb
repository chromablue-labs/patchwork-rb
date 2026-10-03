require "jwt"

module Patchwork
  module BridgeAssertion
    ALLOWED_ALGORITHMS = %w[RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512].freeze
    MAX_TTL = 120
    LEEWAY = 30

    def self.issue(subject:, nonce:, audience:, ttl: MAX_TTL)
      Subject.validate!(subject)
      state = nonce.to_s
      raise ArgumentError, "nonce is required" if state.empty?
      raise ArgumentError, "audience is required" if audience.to_s.empty?
      raise ArgumentError, "ttl must be #{MAX_TTL}s or less" if ttl > MAX_TTL

      now = Time.now.to_i
      claims = {
        sub: subject,
        aud: audience.to_s,
        nonce: state,
        iat: now,
        exp: now + ttl
      }

      JWT.encode(claims, SigningKey.private_key, SigningKey::ALG, { kid: SigningKey.kid })
    end

    def self.verify(token, audience:, nonce:, key: nil)
      expected = nonce.to_s
      raise ArgumentError, "nonce is required" if expected.empty?

      claims = decode(token, audience, key)
      raise InvalidToken, "nonce mismatch" unless SecureCompare.call(claims["nonce"], expected)

      validate_subject!(claims["sub"])
      claims
    end

    def self.validate_subject!(subject)
      Subject.validate!(subject)
    rescue ArgumentError => e
      raise InvalidToken, e.message
    end
    private_class_method :validate_subject!

    def self.decode(token, audience, key)
      JWT.decode(
        token.to_s,
        key || SigningKey.public_key,
        true,
        algorithms: ALLOWED_ALGORITHMS,
        aud: audience.to_s,
        verify_aud: true,
        verify_expiration: true,
        exp_leeway: LEEWAY,
        nbf_leeway: LEEWAY,
        required_claims: %w[sub aud exp nonce]
      ).first
    rescue JWT::DecodeError => e
      raise InvalidToken, e.message
    end
    private_class_method :decode
  end
end

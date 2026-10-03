require "jwt"
require "securerandom"

module Patchwork
  module SessionToken
    PLATFORM_AUDIENCE = "patchwork".freeze

    # Mints the token your frontend hands to Patchwork. `subject` is any string
    # you choose — compose it with Patchwork::Subject.define if it has parts.
    def self.issue(subject:, ttl: nil, connection_id: nil)
      Subject.validate!(subject)

      connection = connection_id.to_s
      raise ArgumentError, "connection_id must be a connection id, not a wildcard" if connection == "*"

      now = Time.now.to_i
      claims = {
        iss: Patchwork.config.issuer!,
        aud: [ PLATFORM_AUDIENCE, Patchwork.config.audience! ],
        sub: subject,
        iat: now,
        exp: now + (ttl || Patchwork.config.token_ttl),
        jti: SecureRandom.uuid,
        act: PLATFORM_AUDIENCE
      }
      claims[:conn] = connection unless connection.empty?

      JWT.encode(claims, SigningKey.private_key, SigningKey::ALG, { kid: SigningKey.kid })
    end

    # Verifies a token you minted, as it comes back to you on a hosted tool
    # call. The algorithm is pinned to RS256 against your own public key, so an
    # HS256 token "signed" with that public key is refused.
    def self.verify(token)
      JWT.decode(
        token.to_s,
        SigningKey.public_key,
        true,
        algorithms: [ SigningKey::ALG ],
        aud: Patchwork.config.audience!,
        verify_aud: true,
        iss: Patchwork.config.issuer!,
        verify_iss: true,
        verify_expiration: true,
        required_claims: %w[sub aud exp iat iss]
      ).first.tap do |claims|
        Subject.validate!(claims["sub"])
        enforce_lifetime!(claims)
      end
    rescue JWT::DecodeError, ArgumentError => e
      raise InvalidToken, e.message
    end

    def self.enforce_lifetime!(claims)
      bound = Patchwork.config.max_token_lifetime
      return if bound.nil?

      lifetime = claims["exp"].to_i - claims["iat"].to_i
      return if lifetime <= bound

      raise LifetimeExceeded, "token lifetime of #{lifetime}s exceeds the #{bound}s bound"
    end
    private_class_method :enforce_lifetime!
  end
end

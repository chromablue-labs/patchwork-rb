require "base64"
require "openssl"

module Patchwork
  module Signature
    SKEW = 300
    HEADER = "Patchwork-Signature".freeze

    # Patchwork sends one v1 per live secret — two during a rotation. The cap
    # stops an unauthenticated header of thousands of candidates from turning
    # verification into a CPU amplifier.
    MAX_SIGNATURES = 8
    MAX_HEADER_BYTES = 1024
    TIMESTAMP = /\A\d{1,12}\z/
    HEX_SHA256 = /\A\h{64}\z/

    Parsed = Struct.new(:timestamp, :signatures, keyword_init: true)

    def self.sign(secret:, timestamp:, method:, path:, body:)
      secret = usable!([ secret ]).first
      mac(secret, payload(timestamp, method, path, digest(body)))
    end

    def self.header(secrets:, timestamp:, method:, path:, body:)
      base = payload(timestamp, method, path, digest(body))
      signatures = usable!(secrets).map { |secret| mac(secret, base) }
      "t=#{timestamp},#{signatures.map { |signature| "v1=#{signature}" }.join(",")}"
    end

    # Structural parse, with no secret and no body. Returns nil for anything
    # Patchwork would never send, so a malformed header is rejected before the
    # body is read.
    def self.parse(header)
      value = header.to_s
      return nil if value.empty? || value.bytesize > MAX_HEADER_BYTES

      pairs = value.split(",").map { |pair| pair.strip.split("=", 2) }
      timestamps = pairs.select { |key, _| key == "t" }.map(&:last)
      signatures = pairs.select { |key, _| key == "v1" }.map(&:last)
      return nil unless timestamps.size == 1 && TIMESTAMP.match?(timestamps.first.to_s)
      return nil if signatures.empty? || signatures.size > MAX_SIGNATURES

      Parsed.new(timestamp: Integer(timestamps.first, 10), signatures: signatures)
    end

    def self.fresh?(parsed, skew: SKEW, now: Time.now.to_i)
      (now - parsed.timestamp).abs <= skew
    end

    def self.verify(secrets:, header:, method:, path:, body:, skew: SKEW, now: Time.now.to_i)
      secrets = usable!(secrets)
      parsed = parse(header)
      return :bad if parsed.nil?
      return :stale unless fresh?(parsed, skew: skew, now: now)

      # The body is hashed once and each secret MACs once, however many
      # candidates the header carries.
      base = payload(parsed.timestamp, method, path, digest(body))
      expected = secrets.map { |secret| mac(secret, base) }
      candidates = parsed.signatures.select { |candidate| HEX_SHA256.match?(candidate) }

      matched = expected.product(candidates).any? { |mine, theirs| secure_compare(mine, theirs) }
      matched ? :ok : :bad
    end

    def self.verify!(secrets:, header:, method:, path:, body:, skew: SKEW, now: Time.now.to_i)
      case verify(secrets: secrets, header: header, method: method, path: path, body: body, skew: skew, now: now)
      when :stale then raise StaleSignature, "signature timestamp outside the #{skew}s window"
      when :bad then raise InvalidSignature, "signature did not match"
      else true
      end
    end

    def self.digest(body)
      Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(body.to_s))
    end
    private_class_method :digest

    def self.payload(timestamp, method, path, digest)
      "#{timestamp}.#{method.to_s.upcase}.#{path}.#{digest}"
    end
    private_class_method :payload

    def self.mac(secret, payload)
      OpenSSL::HMAC.hexdigest("SHA256", secret, payload)
    end
    private_class_method :mac

    # An empty string is a valid HMAC key, so a secret read from an env var that
    # is set but blank — or only whitespace, or a newline from a mounted file —
    # would make every signature forgeable. Refuse it loudly.
    def self.usable!(secrets)
      usable = Array(secrets).map(&:to_s).reject { |secret| secret.strip.empty? }
      raise ConfigurationError, "no signing secret — pass a non-empty secret" if usable.empty?

      usable
    end
    private_class_method :usable!

    def self.secure_compare(expected, candidate)
      SecureCompare.call(expected, candidate)
    end
    private_class_method :secure_compare
  end
end

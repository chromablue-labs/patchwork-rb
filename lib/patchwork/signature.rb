require "base64"
require "openssl"

module Patchwork
  module Signature
    SKEW = 300
    HEADER = "Patchwork-Signature".freeze

    # Patchwork sends one value per live secret per label — two during a
    # rotation. The cap stops an unauthenticated header of thousands of
    # candidates from turning verification into a CPU amplifier.
    MAX_SIGNATURES = 8
    MAX_HEADER_BYTES = 1024
    TIMESTAMP = /\A\d{1,12}\z/
    HEX_SHA256 = /\A\h{64}\z/

    # v1 covers the method, the path and the body. v2 covers the same with the
    # query string, as sent. Its payload carries a "v2." prefix, so a v1
    # signature can never read as a v2 one even where the two cover the same
    # bytes — a request with no query.
    V1 = "v1".freeze
    V2 = "v2".freeze
    LABELS = [ V1, V2 ].freeze

    Parsed = Struct.new(:timestamp, :signatures, keyword_init: true)

    def self.sign(secret:, timestamp:, method:, path:, body:, query: nil, label: V1)
      secret = usable!([ secret ]).first
      mac(secret, payload(label, timestamp, method, path, query, digest(body)))
    end

    def self.header(secrets:, timestamp:, method:, path:, body:, query: nil, labels: nil)
      labels = (labels || (query.nil? ? [ V1 ] : LABELS)).map(&:to_s)
      usable = usable!(secrets)

      values = labels.flat_map do |label|
        base = payload(label, timestamp, method, path, query, digest(body))
        usable.map { |secret| "#{label}=#{mac(secret, base)}" }
      end

      "t=#{timestamp},#{values.join(",")}"
    end

    # Structural parse, with no secret and no body. Returns nil for anything
    # Patchwork would never send, so a malformed header is rejected before the
    # body is read. Unknown labels are ignored rather than refused, so an older
    # reader keeps working when a new one is added.
    def self.parse(header)
      value = header.to_s
      return nil if value.empty? || value.bytesize > MAX_HEADER_BYTES

      pairs = value.split(",").map { |pair| pair.strip.split("=", 2) }
      timestamps = pairs.select { |key, _| key == "t" }.map(&:last)
      return nil unless timestamps.size == 1 && TIMESTAMP.match?(timestamps.first.to_s)

      signatures = LABELS.to_h do |label|
        [ label, pairs.select { |key, _| key == label }.map(&:last) ]
      end
      return nil if signatures.values.all?(&:empty?)
      return nil if signatures.values.any? { |values| values.size > MAX_SIGNATURES }

      Parsed.new(timestamp: Integer(timestamps.first, 10), signatures: signatures)
    end

    def self.fresh?(parsed, skew: SKEW, now: Time.now.to_i)
      (now - parsed.timestamp).abs <= skew
    end

    # Accepts either label. During the migration Patchwork sends both, so a
    # reader that understands v2 must still accept v1 from a platform that has
    # not started sending it.
    # `labels:` narrows what counts. The default accepts either, which is what
    # the migration needs. Pass [V2] to refuse a signature that does not cover
    # the query — stronger, but it fails against a platform still sending v1
    # alone.
    def self.verify(secrets:, header:, method:, path:, body:, query: nil, labels: LABELS,
                    skew: SKEW, now: Time.now.to_i)
      secrets = usable!(secrets)
      accepted = Array(labels).map(&:to_s) & LABELS
      raise ArgumentError, "no known label to verify against" if accepted.empty?

      parsed = parse(header)
      return :bad if parsed.nil?
      return :stale unless fresh?(parsed, skew: skew, now: now)

      # The body is hashed once however many candidates the header carries.
      body_digest = digest(body)

      matched = accepted.any? do |label|
        candidates = parsed.signatures.fetch(label, []).select { |value| HEX_SHA256.match?(value) }
        next false if candidates.empty?

        base = payload(label, parsed.timestamp, method, path, query, body_digest)
        expected = secrets.map { |secret| mac(secret, base) }
        expected.product(candidates).any? { |mine, theirs| secure_compare(mine, theirs) }
      end

      matched ? :ok : :bad
    end

    def self.verify!(secrets:, header:, method:, path:, body:, query: nil, labels: LABELS,
                     skew: SKEW, now: Time.now.to_i)
      case verify(secrets: secrets, header: header, method: method, path: path, body: body,
                  query: query, labels: labels, skew: skew, now: now)
      when :stale then raise StaleSignature, "signature timestamp outside the #{skew}s window"
      when :bad then raise InvalidSignature, "signature did not match"
      else true
      end
    end

    def self.digest(body)
      Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(body.to_s))
    end
    private_class_method :digest

    # The request target: the path as signed by v1, and the path with the query
    # exactly as sent by v2. No query means no "?", because that is what goes
    # on the wire.
    def self.target(label, path, query)
      return path.to_s if label == V1

      value = query.to_s
      value.empty? ? path.to_s : "#{path}?#{value}"
    end
    private_class_method :target

    def self.payload(label, timestamp, method, path, query, digest)
      base = "#{timestamp}.#{method.to_s.upcase}.#{target(label, path, query)}.#{digest}"
      label == V2 ? "#{V2}.#{base}" : base
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

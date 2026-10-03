require "json"
require "uri"

module Patchwork
  module Webhook
    EVENT_HEADER = "Patchwork-Event".freeze
    DELIVERY_HEADER = "Patchwork-Delivery".freeze

    Event = Struct.new(:id, :type, :created_at, :origin, :source, :context, :data, :payload, keyword_init: true) do
      def run_id = payload["run_id"]
      def thread_id = payload["thread_id"]
      def workspace_id = context.is_a?(Hash) ? context["workspace_id"] : nil
      def test? = type == "endpoint.test"
    end

    # Webhooks are keyed with the endpoint's own secret, not the request secret.
    # Pass `secret:`, or `secrets:` with the current and previous during a
    # rotation.
    def self.verify!(body:, signature:, path:, secret: nil, secrets: nil, skew: Signature::SKEW, now: Time.now.to_i)
      raise ArgumentError, "pass secret: or secrets:, not both" if secret && secrets

      Signature.verify!(
        secrets: secrets || [ secret ],
        header: signature,
        method: "POST",
        path: normalize(path),
        body: body,
        skew: skew,
        now: now
      )

      parse(body)
    end

    # Like verify!, but returns nil for a bad or stale signature. A missing
    # secret still raises: that is a deploy problem, not a forged delivery.
    def self.verify(**options)
      verify!(**options)
    rescue InvalidSignature
      nil
    end

    def self.parse(body)
      payload = JSON.parse(body.to_s)
      raise Error, "webhook body is not a JSON object" unless payload.is_a?(Hash)

      Event.new(
        id: payload["id"],
        type: payload["type"],
        created_at: payload["created_at"],
        origin: payload["origin"],
        source: payload["source"],
        context: payload["context"],
        data: payload["data"],
        payload: payload
      )
    rescue JSON::ParserError => e
      raise Error, "webhook body is not JSON: #{e.message}"
    end

    # Only the path is signed — never the host, query or fragment — so accept a
    # registered URL, a path, or request.fullpath and reduce each to the path.
    def self.normalize(path)
      value = path.to_s
      if value.match?(%r{\Ahttps?://}i)
        begin
          value = URI(value).path.to_s
        rescue URI::InvalidURIError
          raise ArgumentError, "path is not a valid URL: #{value.inspect}"
        end
      end
      value = value.split(/[?#]/, 2).first.to_s
      value.empty? ? "/" : value
    end
    private_class_method :normalize
  end
end

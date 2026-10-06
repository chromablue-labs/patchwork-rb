require "json"

module Patchwork
  # The relay half of your mint endpoint: Patchwork asking, server to server,
  # for a token for a subject it already acts for. The Gateway answers it when
  # given `mint_path:`; outside Rack, call Mint.relay from your own route.
  #
  #   result = Patchwork::Mint.relay(body: request.raw_post,
  #                                  signature: request.headers["Patchwork-Signature"],
  #                                  path: request.path)
  #   render json: result, status: :created    # bare { token:, expires_in: }
  module Mint
    BadRequest = Class.new(Error)
    MAX_BODY_BYTES = 16 * 1024

    # Verifies the presenter signature, then mints for exactly the subject in
    # the body — never a default, never a widened one. Raises InvalidSignature,
    # StaleSignature or BadRequest.
    # `query:` is the raw query string the request arrived with. Patchwork signs
    # the query it sends, so a mint_url that carries one needs it here or the
    # v2 value is checked against the bare path. Pass it whenever you have it;
    # the gateway does this for you.
    def self.relay(body:, signature:, path:, secrets: Patchwork.config.request_secrets,
                   connection_id: Patchwork.config.connection_id,
                   query: nil, labels: Signature::LABELS)
      raise BadRequest, "mint body too large" if body.to_s.bytesize > MAX_BODY_BYTES

      Signature.verify!(
        secrets: secrets, header: signature, method: "POST", path: path,
        query: query, body: body, labels: labels
      )
      token = SessionToken.issue(subject: relay_subject(body), connection_id: connection_id)
      { token: token, expires_in: Patchwork.config.token_ttl }
    end

    def self.relay_subject(body)
      payload = JSON.parse(body.to_s)
      raise BadRequest, "mint body must be a JSON object" unless payload.is_a?(Hash)

      subject = payload["subject"]
      Subject.validate!(subject)
    rescue JSON::ParserError
      raise BadRequest, "mint body is not JSON"
    rescue ArgumentError
      raise BadRequest, "mint body has no usable subject"
    end
  end
end

require "digest"
require "json"
require "rack"
require "stringio"

module Patchwork
  # Rack middleware for the calls Patchwork makes to your backend.
  #
  #   use Patchwork::Gateway, resolve: ->(subject, claims) { ... }
  #
  # A request carrying a Patchwork-Signature is verified — signature first, then
  # the session token you minted — and the token's subject is handed to your
  # `resolve`. Whatever it returns is what the request acts as; nil, false or an
  # empty collection is a 401. Requests without the header fall through to your
  # own auth untouched.
  #
  # The gateway never interprets the subject. Pass `subject:` with a format from
  # Patchwork::Subject.define and it decodes for you first, 401ing anything that
  # is not in that format.
  #
  # Pass `mint_path:` and the gateway also answers Patchwork's server-to-server
  # (relay) mint at that path; your own frontend's unsigned mint request at the
  # same path still falls through to your app.
  class Gateway
    SUBJECT_KEY = "patchwork.subject".freeze
    CLAIMS_KEY = "patchwork.claims".freeze
    PRINCIPAL_KEY = "patchwork.principal".freeze
    SIGNATURE_HEADER = "HTTP_PATCHWORK_SIGNATURE".freeze
    MAX_BODY_BYTES = 1024 * 1024
    MAX_CONTROL_BODY_BYTES = 16 * 1024

    TooLarge = Class.new(Error)

    def initialize(app, resolve:, subject: nil, mint_path: nil, health_check: true,
                   health_path: HealthCheck::PATH, max_body_bytes: MAX_BODY_BYTES,
                   replay_guard: nil)
      raise ArgumentError, "resolve must respond to #call" unless resolve.respond_to?(:call)
      raise ArgumentError, "subject must respond to #decode" if subject && !subject.respond_to?(:decode)
      raise ArgumentError, "replay_guard must respond to #call" if replay_guard && !replay_guard.respond_to?(:call)
      raise ArgumentError, "mint_path must be an absolute path" if mint_path && !mint_path.to_s.start_with?("/")
      raise ArgumentError, "health_path must be an absolute path" unless health_path.to_s.start_with?("/")

      @app = app
      @resolve = resolve
      @subject = subject
      @mint_path = mint_path&.to_s
      @health_check = health_check
      @health_path = health_path.to_s
      @max_body_bytes = Integer(max_body_bytes)
      @replay_guard = replay_guard
    end

    def call(env)
      # Only this middleware may say a request is Patchwork's. Anything already
      # in these keys came from somewhere else and is dropped, on every path.
      [ SUBJECT_KEY, CLAIMS_KEY, PRINCIPAL_KEY ].each { |key| env.delete(key) }

      request = Rack::Request.new(env)
      signature = env[SIGNATURE_HEADER].to_s

      return health(request, signature) if @health_check && at?(request, @health_path) && request.post?
      return @app.call(env) if signature.empty?
      return relay_mint(request, signature) if @mint_path && at?(request, @mint_path) && request.post?

      authenticate!(env, request, signature)
      announce(@app.call(env))
    rescue TooLarge
      json(413, { error: "request body too large" })
    rescue InvalidSignature
      unauthorized("invalid signature")
    rescue InvalidToken
      unauthorized("invalid token")
    rescue UnknownSubject
      unauthorized("subject not authorized")
    end

    private

    def authenticate!(env, request, signature)
      verify_signature!(request, signature, limit: @max_body_bytes)

      guard_replay!(request, signature)

      result = Presented.authenticate!(
        authorization: env["HTTP_AUTHORIZATION"],
        resolve: @resolve,
        subject: @subject
      )

      env[SUBJECT_KEY] = result.subject
      env[CLAIMS_KEY] = result.claims
      env[PRINCIPAL_KEY] = result.principal
    end

    # Patchwork's server-to-server mint (the mint-endpoint guide, relay branch):
    # signed, no bearer, the subject in the body. Mint for exactly that subject.
    def relay_mint(request, signature)
      body = verify_signature!(request, signature, limit: MAX_CONTROL_BODY_BYTES)
      subject = Mint.relay_subject(body)
      token = SessionToken.issue(subject: subject, connection_id: Patchwork.config.connection_id)
      json(201, { token: token, expires_in: Patchwork.config.token_ttl })
    rescue Mint::BadRequest => e
      json(400, { error: e.message })
    end

    def health(request, signature)
      body = if signature.empty?
        read_body(request, MAX_CONTROL_BODY_BYTES)
      else
        verify_signature!(request, signature, limit: MAX_CONTROL_BODY_BYTES)
      end

      json(200, HealthCheck.respond(body: body))
    rescue InvalidSignature
      unauthorized("invalid signature")
    rescue HealthCheck::BadRequest
      json(400, { error: "invalid health check" })
    end

    # Header shape and freshness are checked before the body is read, so a
    # garbage or stale header costs nothing but the header.
    def verify_signature!(request, signature, limit:)
      parsed = Signature.parse(signature)
      raise InvalidSignature, "malformed signature" if parsed.nil?
      raise StaleSignature, "stale signature" unless Signature.fresh?(parsed)

      method = signed_method!(request)
      body = read_body(request, limit)
      Signature.verify!(
        secrets: Patchwork.config.request_secrets,
        header: signature,
        method: method,
        path: request.path,
        query: request.query_string,
        body: body
      )
      body
    end

    # Patchwork signs the method it sent and never asks for an override. An
    # override header is not covered by the signature, so a Rack::MethodOverride
    # mounted after the gateway could turn a verified POST into a DELETE; one
    # mounted before it has already rewritten REQUEST_METHOD. Refuse both.
    def signed_method!(request)
      Presented.signed_method!(request.env, request.request_method)
    end

    def guard_replay!(request, signature)
      return unless @replay_guard

      key = "patchwork:replay:#{Digest::SHA256.hexdigest("#{request.request_method} #{request.path} #{signature}")}"
      raise InvalidSignature, "replayed request" unless @replay_guard.call(key, Signature::SKEW * 2)
    end

    # Reads at most `limit` bytes. The verified bytes are handed back to the app
    # as a fresh StringIO, so it sees exactly what was verified whether or not
    # the original input could rewind.
    def read_body(request, limit)
      length = request.content_length.to_i
      raise TooLarge, "declared body exceeds #{limit} bytes" if length > limit

      input = request.env["rack.input"]
      body = input ? input.read(limit + 1).to_s : +""
      raise TooLarge, "body exceeds #{limit} bytes" if body.bytesize > limit

      request.env["rack.input"] = StringIO.new(body)
      body
    end

    # The path Patchwork signed is SCRIPT_NAME + PATH_INFO; the route is
    # matched on either, so the gateway also works mounted under a prefix.
    def at?(request, path)
      request.path == path || request.path_info == path
    end

    def unauthorized(message)
      json(401, { error: message })
    end

    # Only a verified call gets the header. A request that fell through carries
    # the consumer's own traffic, and Patchwork is not reading it.
    def announce(response)
      status, headers, body = response
      [ status, headers.merge(SDK_HEADER => SDK), body ]
    end

    def json(status, payload)
      body = JSON.generate(payload)
      [ status, {
        "content-type" => "application/json",
        "content-length" => body.bytesize.to_s,
        SDK_HEADER => SDK
      }, [ body ] ]
    end
  end
end

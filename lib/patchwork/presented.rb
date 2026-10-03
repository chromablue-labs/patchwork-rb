module Patchwork
  module Presented
    Result = Struct.new(:subject, :claims, :principal, keyword_init: true)

    def self.authenticate!(authorization:, resolve:, subject: nil)
      claims = SessionToken.verify(bearer(authorization))
      presented = claims["sub"]
      principal = resolve_principal(resolve, subject, presented, claims)
      raise UnknownSubject, "subject was not resolved" if refused?(principal)

      Result.new(subject: presented, claims: claims, principal: principal)
    end

    def self.signed_method!(env, request_method)
      raise InvalidSignature, "method override on a signed request" if env.key?("HTTP_X_HTTP_METHOD_OVERRIDE")

      original = env["rack.methodoverride.original_method"]
      raise InvalidSignature, "method override on a signed request" if original && original != request_method

      request_method
    end

    def self.bearer(authorization)
      token = authorization.to_s[/\ABearer ([A-Za-z0-9_\-.=]+)\z/, 1]
      raise InvalidToken, "no bearer token" if token.nil?

      token
    end

    def self.resolve_principal(resolve, format, presented, claims)
      argument = presented
      if format
        argument = format.decode(presented)
        raise UnknownSubject, "subject is not in the expected format" if argument.nil?
      end

      takes_claims?(resolve) ? resolve.call(argument, claims) : resolve.call(argument)
    end

    def self.refused?(principal)
      return true unless principal
      return principal.empty? if principal.respond_to?(:empty?) && !principal.is_a?(String)

      principal.is_a?(String) && principal.empty?
    end

    def self.takes_claims?(callable)
      parameters = callable.respond_to?(:parameters) ? callable.parameters : callable.method(:call).parameters
      positional = parameters.count { |type, _| type == :req || type == :opt }
      parameters.any? { |type, _| type == :rest } || positional >= 2
    end
  end
end

require "patchwork/version"
require "patchwork/errors"
require "patchwork/configuration"
require "patchwork/secure_compare"
require "patchwork/signature"
require "patchwork/signing_key"
require "patchwork/subject"
require "patchwork/session_token"
require "patchwork/presented"
require "patchwork/webhook"
require "patchwork/health_check"
require "patchwork/mint"
require "patchwork/bridge_assertion"

module Patchwork
  # Announced on a response to a verified Patchwork call, so the platform can
  # tell which version a workspace runs and retire an old signature label on
  # evidence rather than a guess. Lowercase, as Rack 3 requires.
  SDK_HEADER = "patchwork-sdk".freeze
  SDK = "patchwork-rb/#{VERSION}".freeze
end

module Patchwork
  class << self
    def config
      @config ||= Configuration.new
    end

    def configure
      yield config
      SigningKey.reset!
      config
    end

    def reset!
      @config = Configuration.new
      SigningKey.reset!
    end
  end
end

# The gateway is optional: it is defined only when Rack is available. Only a
# missing Rack is tolerated — any other LoadError in the gateway still raises.
begin
  require "rack"
rescue LoadError
  nil
end
require "patchwork/gateway" if defined?(Rack)

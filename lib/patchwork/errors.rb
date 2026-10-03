module Patchwork
  Error = Class.new(StandardError)
  ConfigurationError = Class.new(Error)
  InvalidToken = Class.new(Error)
  LifetimeExceeded = Class.new(InvalidToken)
  InvalidSignature = Class.new(Error)
  StaleSignature = Class.new(InvalidSignature)
  UnknownSubject = Class.new(Error)
end

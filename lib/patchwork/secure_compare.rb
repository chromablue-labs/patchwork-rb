require "openssl"

module Patchwork
  module SecureCompare
    def self.call(expected, candidate)
      expected = expected.to_s
      candidate = candidate.to_s
      return false unless expected.bytesize == candidate.bytesize

      OpenSSL.fixed_length_secure_compare(expected, candidate)
    end
  end
end

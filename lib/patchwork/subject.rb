module Patchwork
  # A subject is an opaque string you choose. Patchwork stores it, partitions
  # threads and memory on it, and hands it back on every tool call — it never
  # parses it. So this gem never parses it either, unless you ask it to.
  #
  # Two levels:
  #
  #   Patchwork::Subject.validate!("ticket:8821")   # any shape, just checked
  #
  #   Membership = Patchwork::Subject.define(:user_id, :workspace_id)
  #   Membership.encode(user_id: "usr_1", workspace_id: "ws_acme")  # => "usr_1:ws_acme"
  #   Membership.decode("usr_1:ws_acme").workspace_id                # => "ws_acme"
  #
  # A definition is a format *you* declare, with as many parts as your isolation
  # boundary needs, an optional namespace prefix, and your own delimiter.
  module Subject
    DEFAULT_DELIMITER = ":".freeze

    # The rules every subject obeys, composed or not. Patchwork itself rejects
    # only the empty string; the gem also rejects surrounding whitespace, because
    # a trailing space from a template silently creates a second partition.
    def self.validate!(subject)
      raise ArgumentError, "subject must be a String, got #{subject.class}" unless subject.is_a?(String)

      text = utf8(subject)
      raise ArgumentError, "subject must be valid UTF-8" if text.nil?
      raise ArgumentError, "subject must not be empty" if text.empty?
      raise ArgumentError, "subject must not have leading or trailing whitespace" if padded?(text)
      raise ArgumentError, "subject must not contain control characters" if CONTROL.match?(text)

      subject
    end

    # Unicode whitespace, not just ASCII: a non-breaking space pasted from HTML
    # is the same silent second partition as a trailing ASCII space.
    EDGE_SPACE = /\A[[:space:]\u200B\u2060\uFEFF]|[[:space:]\u200B\u2060\uFEFF]\z/
    # CR and LF matter beyond hygiene: in relay the subject travels in a header.
    CONTROL = /[[:cntrl:]]/

    def self.padded?(text)
      EDGE_SPACE.match?(text)
    end

    # Returns a UTF-8 copy, or nil when the bytes are not valid in their own
    # encoding or have no UTF-8 form. Never raises on hostile input.
    def self.utf8(value)
      return nil unless value.valid_encoding?

      text = value.encoding == Encoding::UTF_8 ? value : value.encode(Encoding::UTF_8)
      text.valid_encoding? ? text : nil
    rescue EncodingError
      nil
    end

    def self.define(*parts, delimiter: DEFAULT_DELIMITER, prefix: nil)
      Format.new(parts, delimiter: delimiter, prefix: prefix)
    end

    class Format
      attr_reader :parts, :delimiter, :prefix

      def initialize(parts, delimiter:, prefix:)
        raise ArgumentError, "define at least one part" if parts.empty?
        raise ArgumentError, "parts must be symbols" unless parts.all?(Symbol)
        raise ArgumentError, "parts must be unique" unless parts.uniq.size == parts.size
        parts.each { |part| name!(part) }
        raise ArgumentError, "delimiter must be a non-empty String" unless delimiter.is_a?(String) && !delimiter.empty?

        text = Subject.utf8(delimiter)
        if text.nil? || /[[:space:][:cntrl:]]/.match?(text)
          raise ArgumentError, "delimiter must be valid UTF-8 with no whitespace or control characters"
        end

        @parts = parts.freeze
        @delimiter = text.dup.freeze
        @prefix = prefix&.to_s&.then { |value| component!(:prefix, value) }&.freeze
        @ref = Struct.new(*parts, keyword_init: true)
        freeze
      end

      # Keyword-only, so the order of the parts is fixed by the definition and
      # never by a call site — a flipped order is a different subject.
      def encode(**values)
        missing = parts - values.keys
        unknown = values.keys - parts
        raise ArgumentError, "missing subject parts: #{missing.join(', ')}" if missing.any?
        raise ArgumentError, "unknown subject parts: #{unknown.join(', ')}" if unknown.any?

        segments = parts.map { |part| component!(part, values[part].to_s) }
        subject = [ prefix, *segments ].compact.join(delimiter)

        # With a multi-character delimiter a part can end with half of it
        # ("acme:" + "::" + "x"), making two tuples encode to one string. The
        # only complete check is that the string decodes back to what went in.
        unless decode(subject)&.to_h == parts.zip(segments).to_h
          raise ArgumentError, "subject parts are ambiguous with the delimiter #{delimiter.inspect}"
        end

        subject
      end

      # Returns a struct with one reader per part, or nil when the subject is not
      # in this format. Never guesses: the part count must match exactly.
      def decode(subject)
        return nil unless subject.is_a?(String)

        body = Subject.utf8(subject)
        return nil if body.nil?
        if prefix
          head = "#{prefix}#{delimiter}"
          return nil unless body.start_with?(head)

          body = body.delete_prefix(head)
        end

        segments = body.split(delimiter, -1)
        return nil unless segments.size == parts.size
        return nil if segments.any? { |segment| segment.empty? || Subject.padded?(segment) || CONTROL.match?(segment) }

        @ref.new(**parts.zip(segments).to_h).freeze
      end

      def decode!(subject)
        decode(subject) || raise(UnknownSubject, "subject is not in the #{inspect} format")
      end

      def match?(subject)
        !decode(subject).nil?
      end

      def inspect
        "#<Patchwork::Subject #{[ prefix, *parts.map { |part| "<#{part}>" } ].compact.join(delimiter)}>"
      end
      alias to_s inspect

      private

      # A part containing the delimiter makes the string ambiguous to decode, so
      # it is refused at encode time rather than mis-split later.
      def component!(name, value)
        text = Subject.utf8(value)
        raise ArgumentError, "subject part #{name} must be valid UTF-8" if text.nil?
        raise ArgumentError, "subject part #{name} is empty" if text.empty?
        raise ArgumentError, "subject part #{name} contains the delimiter #{delimiter.inspect}" if text.include?(delimiter)
        raise ArgumentError, "subject part #{name} has leading or trailing whitespace" if Subject.padded?(text)
        raise ArgumentError, "subject part #{name} contains control characters" if CONTROL.match?(text)

        text
      end

      # A part named like a Struct method (:freeze, :hash, :class, :to_h)
      # would shadow it on the decoded ref, so decode could hand back a part's
      # raw string where a frozen ref was expected.
      RESERVED = Struct.new(:placeholder).new.public_methods.freeze

      def name!(part)
        raise ArgumentError, "part #{part.inspect} must be a lowercase identifier" unless /\A[a-z_][a-z0-9_]*\z/.match?(part)
        raise ArgumentError, "part #{part.inspect} clashes with a Struct method" if RESERVED.include?(part)
      end
    end
  end
end

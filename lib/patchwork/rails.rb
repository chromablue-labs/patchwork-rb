require "active_support/concern"
require "patchwork"

module Patchwork
  module Rails
    module Presented
      extend ActiveSupport::Concern

      included do
        before_action :verify_patchwork_call!
      end

      class_methods do
        def patchwork_subject_format(format = nil)
          @patchwork_subject_format = format if format
          return @patchwork_subject_format if defined?(@patchwork_subject_format) && @patchwork_subject_format
          return unless superclass.respond_to?(:patchwork_subject_format)

          superclass.patchwork_subject_format
        end
      end

      private

      def verify_patchwork_call!
        signature = request.headers[::Patchwork::Signature::HEADER].to_s
        raise ::Patchwork::InvalidSignature, "missing signature" if signature.empty?

        signed = ::Patchwork::Presented.signed_method!(request.env, request.request_method)
        ::Patchwork::Signature.verify!(
          secrets: ::Patchwork.config.request_secrets,
          header: signature,
          method: signed,
          path: request.path,
          query: request.query_string,
          body: request.raw_post
        )

        result = ::Patchwork::Presented.authenticate!(
          authorization: request.headers["Authorization"],
          resolve: method(:patchwork_resolve),
          subject: self.class.patchwork_subject_format
        )

        @patchwork_subject = result.subject
        @patchwork_claims = result.claims
        @patchwork_principal = result.principal
        response.headers[::Patchwork::SDK_HEADER] = ::Patchwork::SDK
      rescue ::Patchwork::StaleSignature
        deny_patchwork_call("stale signature")
      rescue ::Patchwork::InvalidSignature
        deny_patchwork_call("invalid signature")
      rescue ::Patchwork::InvalidToken
        deny_patchwork_call("invalid token")
      rescue ::Patchwork::UnknownSubject
        deny_patchwork_call("subject not authorized")
      end

      def patchwork_resolve(_subject)
        raise ::Patchwork::ConfigurationError,
              "#{self.class.name} must define patchwork_resolve(subject) — return the principal " \
              "the call acts as, or nil to refuse it"
      end

      def deny_patchwork_call(message)
        render json: { error: message }, status: :unauthorized
      end

      attr_reader :patchwork_subject, :patchwork_claims, :patchwork_principal
    end
  end
end

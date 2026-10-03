require_relative "lib/patchwork/version"

Gem::Specification.new do |spec|
  spec.name = "patchwork-rb"
  spec.version = Patchwork::VERSION
  spec.authors = [ "Chromablue Labs" ]
  spec.summary = "Ruby SDK for Patchwork — mint session tokens, verify tool calls and webhooks"
  spec.description = "Server-side helpers for integrating with Patchwork: RS256 session tokens, " \
                     "HMAC request signing and verification, webhook signature verification, " \
                     "and Rack middleware for the tool calls Patchwork makes to your backend."
  spec.homepage = "https://usepatchwork.co"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"

  repo = "https://github.com/chromablue-labs/patchwork-rb"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["documentation_uri"] = "#{repo}#readme"
  spec.metadata["source_code_uri"] = repo
  spec.metadata["changelog_uri"] = "#{repo}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{repo}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Ship what git tracks, not whatever happens to be on disk at build time.
  tracked = Dir.chdir(__dir__) { `git ls-files -z -- lib README.md LICENSE 2>/dev/null`.split("\x0") }
  spec.files = tracked.empty? ? Dir["lib/**/*.rb", "README.md", "LICENSE"] : tracked
  spec.require_paths = [ "lib" ]

  # GHSA-c32j-vqhx-rx3x (empty-key HMAC bypass) affects < 2.10.3 and 3.0.0-3.1.x.
  # RS256 is pinned so the gem is not exploitable through it, but consumers
  # should not resolve to a vulnerable jwt because of us.
  spec.add_dependency "jwt", ">= 2.10.3", "< 4.0", "!= 3.0.0", "!= 3.1.0", "!= 3.1.1", "!= 3.1.2"
end

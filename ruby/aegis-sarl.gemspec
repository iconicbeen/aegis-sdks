# frozen_string_literal: true

require_relative "lib/aegis_sarl"

Gem::Specification.new do |spec|
  spec.name = "aegis-sarl"
  spec.version = Aegis::VERSION
  spec.summary = "Aegis in-app firewall: Rack middleware that reports, and blocks only when told to."
  spec.authors = ["Aegis"]
  spec.license = "MIT"
  spec.files = ["lib/aegis_sarl.rb", "README.md"]
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.1"
  # No runtime dependencies, on purpose. See README.
end

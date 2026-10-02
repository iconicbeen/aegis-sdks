# frozen_string_literal: true

# Prints this SDK's verdict for each corpus case, so the shared parity test
# can compare Ruby against the other SDKs.
require "json"
require_relative "lib/aegis_sarl"

cases = JSON.parse($stdin.read)
out = cases.to_h do |c|
  [c, Aegis::RULES.select { |r| r.pattern.match?(c) }.map(&:id).sort]
end
puts JSON.generate(out)

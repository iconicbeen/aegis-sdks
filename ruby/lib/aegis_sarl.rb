# frozen_string_literal: true

require "json"
require "stringio"
require "net/http"
require "uri"
require "time"

# Aegis in-app firewall for Ruby: Rack middleware for Rails, Sinatra, Hanami,
# or anything else that speaks Rack.
#
# A port of the Node, Python, Go, Java, .NET and PHP SDKs, holding the same
# four properties, because they are the reason this is safe to put in a
# request path at all:
#
#   - It never blocks unless explicitly configured to.
#   - It never raises into the request path; an error inside the firewall
#     lets the request continue rather than returning a 500.
#   - It reports on a background thread, so the user never waits for the
#     control plane.
#   - It holds no unbounded state: the event queue is capped and drops.
#
# The detection rules are identical to the other SDKs', verified by the
# shared corpus in the platform test `sdk-parity-e2e.test.ts`. Two SDKs that
# disagree about what an attack looks like produce findings that cannot be
# compared across services, and the quieter one silently becomes the weakest
# link.
#
# No dependencies, not even the rack gem: the Rack interface is a callable
# taking an env hash, and every dependency is a supply-chain risk a security
# tool has no business introducing.
#
#   use Aegis::Middleware, url: "https://aegis.example.com",
#                          token: ENV.fetch("AEGIS_TOKEN"),
#                          app_name: "checkout"
module Aegis
  VERSION = "0.1.0"

  Rule = Struct.new(:id, :severity, :pattern, keyword_init: true)

  # Deliberately conservative. A false positive here rejects a real user's
  # request, so each pattern targets syntax with no legitimate reason to
  # appear in a parameter value, rather than merely suspicious words.
  #
  # Ruby's `\b` and character classes match the other engines' on this
  # corpus; `\A`/`\z` are not used because no rule is anchored.
  RULES = [
    # UNION followed by SELECT is not something a search box sends.
    Rule.new(id: "sqli-union", severity: "critical", pattern: /\bunion\b[\s\S]{0,40}\bselect\b/i),
    # The quote structure is required so that "1=1" in prose does not match.
    Rule.new(id: "sqli-tautology", severity: "high",
             pattern: /['"]\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i),
    Rule.new(id: "path-traversal", severity: "high", pattern: %r{(\.\.[/\\]){2,}|%2e%2e[/\\%]}i),
    # A shell metacharacter immediately followed by a known binary.
    Rule.new(id: "command-injection", severity: "critical",
             pattern: /[;|&`$]\s*(cat|curl|wget|nc|bash|sh|python|perl)\b/i),
    Rule.new(id: "xss-script", severity: "high", pattern: /<script[\s>]|javascript:\s*[a-z]|\bonerror\s*=/i),
    # The cloud metadata endpoints, which a user parameter never needs.
    Rule.new(id: "ssrf-metadata", severity: "critical",
             pattern: /169\.254\.169\.254|metadata\.google\.internal/i),
  ].freeze

  QUEUE_LIMIT = 1000

  module_function

  # The rules matching any of the given inputs.
  def inspect_values(values)
    RULES.select do |rule|
      values.any? { |value| !value.nil? && !value.empty? && rule.pattern.match?(value) }
    end
  end

  # Truncates an address, so the SDK never reports a full client IP.
  def client_prefix(address)
    return "unknown" if address.nil? || address.empty?

    clean = address.start_with?("::ffff:") ? address[7..] : address
    # An IPv4 address with a port has exactly one colon; an IPv6 address has
    # several, and stripping its last group would corrupt it.
    clean = clean.split(":").first if clean.count(":") == 1
    return "#{clean.split(':').first(3).join(':')}::" if clean.include?(":")

    octets = clean.split(".")
    return "unknown" unless octets.length == 4

    "#{octets[0]}.#{octets[1]}.#{octets[2]}.0"
  end

  # Percent-decodes, returning the input unchanged if it will not decode.
  def decode_safely(value)
    decoded = URI.decode_www_form_component(value)
    decoded.valid_encoding? ? decoded : value
  rescue ArgumentError
    value
  end

  # Anchored glob. Only a trailing `*` is supported, so a pattern cannot
  # backtrack.
  def path_matches?(path, pattern)
    return path.start_with?(pattern[0...-1]) if pattern.end_with?("*")

    path == pattern
  end

  def worst(rules)
    rules.find { |r| r.severity == "critical" } || rules.first
  end

  # What happens to a request that matched rules. Anything uncertain logs
  # rather than blocks, and every decision carries why: an engineer looking
  # at a blocked request at 3am needs to know in seconds whether to disable a
  # rule.
  def decide(policy, path, matched)
    override = (policy[:overrides] || []).find { |o| path_matches?(path, o[:pattern]) }
    mode = override ? override[:mode] : (policy[:default_mode] || "monitor")

    if mode == "off"
      reason = override ? "Protection is disabled for #{override[:pattern]}: #{override[:reason]}" : "Protection is disabled."
      return { action: "allow", reason: reason, rule_id: nil }
    end

    exempt = override ? (override[:exempt_rules] || []) : []
    applicable = matched.reject { |r| exempt.include?(r.id) }
    return { action: "allow", reason: "Nothing applicable matched.", rule_id: nil } if applicable.empty?

    rule = worst(applicable)
    if mode == "block" && (policy[:blocking_rules] || []).include?(rule.id)
      return { action: "block",
               reason: "Blocked: #{rule.id} (#{rule.severity}) matched and is enabled for blocking.",
               rule_id: rule.id }
    end
    if mode == "block"
      # Matched, but not a rule the operator allowed to block. Logging is the
      # conservative reading.
      return { action: "log",
               reason: "#{rule.id} (#{rule.severity}) matched but is not in the blocking rule list.",
               rule_id: rule.id }
    end

    { action: "log",
      reason: "#{rule.id} (#{rule.severity}) matched. Endpoint is in monitor mode, so the request continues.",
      rule_id: rule.id }
  end

  # A policy can never escalate monitor mode into blocking. That is the
  # second of the two opt-ins blocking requires.
  def effective_policy(config)
    return { default_mode: "monitor", overrides: [], blocking_rules: [] } unless config[:mode] == "block"
    return config[:policy] if config[:policy]

    # Without this, mode "block" would quietly block nothing: a shared default
    # carries no blocking rules on purpose. The caller has asked for
    # blocking, so every rule the SDK can detect is eligible.
    { default_mode: "block", overrides: [], blocking_rules: RULES.map(&:id) }
  end

  # Evaluates a request description. Pure, so it can be tested exhaustively;
  # the middleware builds the description from the Rack env.
  def evaluate(config, request)
    path = request[:path] || "/"
    query = request[:query] || ""
    # Both raw and decoded. A percent-encoded space defeats every pattern
    # containing one, and a double-encoded payload only makes sense raw.
    values = [path, query, decode_safely(query), decode_safely(path)]
    # Headers an attacker controls and applications commonly trust.
    %w[referer x-forwarded-for user-agent].each do |name|
      value = request.dig(:headers, name).to_s
      values << value[0, 2000] unless value.empty?
    end
    body = request[:body].to_s
    values << body[0, 10_000] unless body.empty?

    matched = inspect_values(values)
    return { decision: nil, event: nil } if matched.empty?

    decision = decide(effective_policy(config), path, matched)
    rule = worst(matched)
    {
      decision: decision,
      event: {
        at: Time.now.utc.iso8601,
        method: request[:method] || "GET",
        path: path,
        ruleId: rule.id,
        severity: rule.severity,
        clientPrefix: client_prefix(request[:remote_address]),
        userAgent: request.dig(:headers, "user-agent").to_s[0, 300],
        blocked: decision[:action] == "block",
        # Why, recorded at the time. Reconstructing a decision from policy
        # after the fact is guesswork once it has changed.
        reason: decision[:reason],
      },
    }
  rescue StandardError => e
    # Never raise into the request path.
    config[:on_error]&.call(e)
    { decision: nil, event: nil }
  end

  # Sends events on one background thread, from a bounded queue.
  class Reporter
    def initialize(url:, token:, app_name:, on_error: nil)
      @endpoint = URI("#{url.to_s.chomp('/')}/api/public/runtime/events")
      @token = token.to_s
      @app_name = app_name || "ruby"
      @on_error = on_error
      @queue = Queue.new
      @thread = nil
      @lock = Mutex.new
    end

    # Bounded: the application's memory matters more than these events.
    def record(event)
      return if @queue.size >= QUEUE_LIMIT

      @queue << event
      start
    end

    def pending
      @queue.size
    end

    # Sends everything queued now. Used by the thread and by tests.
    def flush
      events = []
      events << @queue.pop(true) until @queue.empty?
      return if events.empty?

      post(events)
    rescue ThreadError
      nil
    end

    private

    def start
      @lock.synchronize do
        return if @thread&.alive?

        @thread = Thread.new do
          Thread.current.report_on_exception = false
          loop do
            batch = [@queue.pop]
            begin
              batch << @queue.pop(true) while batch.size < 100
            rescue ThreadError
              # Drained; send what was collected.
            end
            post(batch)
          end
        end
      end
    end

    # Failures are dropped, never retried forever.
    def post(events)
      http = Net::HTTP.new(@endpoint.host, @endpoint.port)
      http.use_ssl = @endpoint.scheme == "https"
      http.open_timeout = 5
      http.read_timeout = 10
      req = Net::HTTP::Post.new(@endpoint)
      req["content-type"] = "application/json"
      req["authorization"] = "Bearer #{@token}"
      req.body = JSON.generate(app: @app_name, events: events)
      http.request(req)
    rescue StandardError => e
      @on_error&.call(e)
    end
  end

  # Rack middleware.
  class Middleware
    attr_reader :reporter

    def initialize(app, url: nil, token: nil, app_name: "ruby", mode: "monitor", policy: nil,
                   max_body_bytes: 65_536, on_error: nil)
      @app = app
      @config = { mode: mode, policy: policy, on_error: on_error }
      @max_body_bytes = max_body_bytes
      @reporter = url ? Reporter.new(url: url, token: token, app_name: app_name, on_error: on_error) : nil
    end

    def call(env)
      decision = protect(env)
      if decision && decision[:action] == "block"
        # Deliberately terse: naming the rule would tell an attacker exactly
        # what to change.
        return [403, { "content-type" => "application/json" }, ['{"error":"Request rejected."}']]
      end

      @app.call(env)
    end

    private

    def protect(env)
      result = Aegis.evaluate(@config, describe(env))
      @reporter&.record(result[:event]) if result[:event]
      result[:decision]
    rescue StandardError => e
      # Never raise into the request path, including from reading the env.
      @config[:on_error]&.call(e)
      nil
    end

    def describe(env)
      headers = {}
      env.each do |key, value|
        next unless key.is_a?(String) && key.start_with?("HTTP_")

        headers[key[5..].downcase.tr("_", "-")] = value.to_s
      end
      {
        method: env["REQUEST_METHOD"],
        path: env["PATH_INFO"].to_s.empty? ? "/" : env["PATH_INFO"],
        query: env["QUERY_STRING"].to_s,
        headers: headers,
        remote_address: env["REMOTE_ADDR"],
        body: read_body(env),
      }
    end

    # Reads the body for inspection and hands the application the same bytes.
    #
    # Rack 3 no longer requires `rack.input` to be rewindable, and under
    # WEBrick it is not: reading and then calling `rewind` left the
    # application an empty body -- measured, the echo app received "" for a
    # 36-byte POST. So the bytes read are put back as a fresh StringIO rather
    # than trusting the stream to rewind. Bounded, so a large upload is
    # neither buffered twice nor inspected.
    def read_body(env)
      length = env["CONTENT_LENGTH"].to_i
      input = env["rack.input"]
      return "" if input.nil? || length <= 0 || length > @max_body_bytes

      body = input.read(length).to_s
      env["rack.input"] = StringIO.new(body)
      body
    end
  end
end

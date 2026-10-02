# frozen_string_literal: true

# The Ruby SDK against real HTTP: a WEBrick server running the middleware in
# front of an echo app, and a second server collecting what it reports.
#
# Run inside a Ruby container (see the platform test `sdk-ruby-e2e.test.ts`);
# `rack`, `rackup` and `webrick` are test-only, never runtime dependencies.
require "minitest/autorun"
require "json"
require "net/http"
require "socket"
require "rackup"
require "webrick"
require_relative "lib/aegis_sarl"

module Harness
  module_function

  def free_port
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    server.close
    port
  end

  def serve(app, port)
    server = WEBrick::HTTPServer.new(BindAddress: "127.0.0.1", Port: port,
                                     Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
    server.mount "/", Rackup::Handler::WEBrick, app
    Thread.new { server.start }
    50.times do
      begin
        TCPSocket.new("127.0.0.1", port).close
        return server
      rescue Errno::ECONNREFUSED
        sleep 0.05
      end
    end
    raise "server on #{port} did not start"
  end

  def request(port, path, body: nil)
    uri = URI("http://127.0.0.1:#{port}#{path}")
    req = body ? Net::HTTP::Post.new(uri) : Net::HTTP::Get.new(uri)
    if body
      req["content-type"] = "application/json"
      req.body = body
    end
    Net::HTTP.start(uri.host, uri.port) { |http| http.request(req) }
  end
end

# Records every report the SDK sends, keyed by the app name each test gives
# its firewall.
#
# One shared queue made the suite flaky: each middleware's reporter thread
# outlives its test, so a report from one test could arrive after the next
# test had cleared the queue, and that test read an event it never caused --
# measured, 3 of 6 seeded runs failed that way. Keying by app name means a
# test only ever reads its own reports, however late another's arrive.
COLLECTED = Hash.new { |h, k| h[k] = Queue.new }
COLLECTED_LOCK = Mutex.new
COLLECTOR_PORT = Harness.free_port
COLLECTOR = Harness.serve(lambda { |env|
  if env["PATH_INFO"] == "/api/public/runtime/events"
    report = JSON.parse(env["rack.input"].read)
    COLLECTED_LOCK.synchronize { COLLECTED[report["app"]] } << report
  end
  [200, { "content-type" => "application/json" }, ["{}"]]
}, COLLECTOR_PORT)

ECHO = lambda { |env|
  [200, { "content-type" => "application/json" },
   [JSON.generate(ok: true, received: env["rack.input"].read.to_s)]]
}

def firewall(app_name:, **options)
  Aegis::Middleware.new(ECHO, url: "http://127.0.0.1:#{COLLECTOR_PORT}", token: "test-token",
                              app_name: app_name, **options)
end

def next_report(app_name, timeout = 5)
  queue = COLLECTED_LOCK.synchronize { COLLECTED[app_name] }
  deadline = Time.now + timeout
  until Time.now > deadline
    begin
      return queue.pop(true)
    rescue ThreadError
      sleep 0.05
    end
  end
  nil
end

class MonitorModeTest < Minitest::Test
  def setup
    @app = "ruby-#{name}"
    @port = Harness.free_port
    @server = Harness.serve(firewall(app_name: @app), @port)
  end

  def teardown
    @server.shutdown
  end

  def test_an_attack_passes_through_and_is_reported
    res = Harness.request(@port, "/search?q=1%20union%20select%20password")
    # Monitor is the default so that installing the SDK cannot cause an outage.
    assert_equal "200", res.code
    report = next_report(@app)
    refute_nil report, "monitor mode still reports the attack"
    event = report["events"].first
    assert_equal "sqli-union", event["ruleId"]
    assert_equal false, event["blocked"]
    assert_equal @app, report["app"]
    # A full client IP is personal data the control plane has no use for.
    assert_equal "127.0.0.0", event["clientPrefix"]
  end

  def test_the_application_still_receives_the_body
    body = JSON.generate(comment: "'; cat /etc/passwd")
    res = Harness.request(@port, "/comments", body: body)
    assert_equal body, JSON.parse(res.body)["received"]
    assert_equal "command-injection", next_report(@app)["events"].first["ruleId"]
  end

  def test_ordinary_traffic_is_not_reported
    Harness.request(@port, "/search?q=union+station+opening+hours")
    assert_nil next_report(@app, 1)
  end
end

class BlockModeTest < Minitest::Test
  def setup
    @app = "ruby-#{name}"
    @port = Harness.free_port
  end

  def teardown
    @server&.shutdown
  end

  def test_block_mode_rejects_without_reaching_the_app_or_naming_the_rule
    @server = Harness.serve(firewall(app_name: @app, mode: "block"), @port)
    res = Harness.request(@port, "/search?q=1%20union%20select%201")
    assert_equal "403", res.code
    assert_includes res.body, "Request rejected"
    refute_includes res.body, "sqli-union"
    refute_includes res.body, "ok"
    assert_equal true, next_report(@app)["events"].first["blocked"]
  end

  # The bug found in the Python port: a query string arrives percent-encoded,
  # so %20 defeats every pattern containing a space.
  def test_a_percent_encoded_payload_is_decoded_before_matching
    @server = Harness.serve(firewall(app_name: @app, mode: "block"), @port)
    assert_equal "403", Harness.request(@port, "/x?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E").code
  end

  def test_a_per_endpoint_override_monitors_one_path_and_blocks_the_rest
    policy = {
      default_mode: "block",
      overrides: [{ pattern: "/webhooks/*", mode: "monitor",
                    reason: "Third-party payloads look like attacks and we do not control them." }],
      blocking_rules: %w[sqli-union command-injection],
    }
    @server = Harness.serve(firewall(app_name: @app, mode: "block", policy: policy), @port)
    assert_equal "200", Harness.request(@port, "/webhooks/stripe?q=union%20select%201").code
    assert_equal "403", Harness.request(@port, "/api/orders?q=union%20select%201").code
  end

  # Blocking takes two separate opt-ins; a policy alone cannot escalate.
  def test_a_blocking_policy_without_block_mode_does_not_block
    policy = { default_mode: "block", overrides: [], blocking_rules: %w[sqli-union] }
    @server = Harness.serve(firewall(app_name: @app, policy: policy), @port)
    assert_equal "200", Harness.request(@port, "/x?q=union%20select%201").code
  end
end

class FailureTest < Minitest::Test
  def test_an_error_inside_the_firewall_lets_the_request_through
    errors = []
    # An input that fails when the firewall reads it. The application does
    # not read it, so any error seen is the firewall's own, and the request
    # must still reach the application rather than becoming a 500.
    input = Object.new
    def input.read(*) = raise(IOError, "boom")
    app = ->(_env) { [200, {}, ["ok"]] }
    broken = Aegis::Middleware.new(app, mode: "block", on_error: ->(e) { errors << e })
    status, = broken.call("REQUEST_METHOD" => "POST", "PATH_INFO" => "/", "QUERY_STRING" => "",
                          "CONTENT_LENGTH" => "5", "rack.input" => input)
    assert_equal 200, status
    assert_equal 1, errors.size
  end

  def test_an_unreachable_collector_never_raises
    errors = Queue.new
    reporter = Aegis::Reporter.new(url: "http://127.0.0.1:1", token: "t", app_name: "x",
                                   on_error: ->(e) { errors << e })
    reporter.record({ ruleId: "x" })
    deadline = Time.now + 5
    sleep 0.05 while errors.empty? && Time.now < deadline
    refute errors.empty?, "the failure is reported to on_error, not raised"
  end

  def test_the_queue_is_bounded
    reporter = Aegis::Reporter.new(url: "http://127.0.0.1:1", token: "t", app_name: "x")
    reporter.instance_variable_set(:@thread, Thread.new { sleep }) # keep the sender idle
    (Aegis::QUEUE_LIMIT + 50).times { reporter.record({ ruleId: "x" }) }
    assert_equal Aegis::QUEUE_LIMIT, reporter.pending
  end
end

class PureDecisionTest < Minitest::Test
  def test_globs_are_anchored_and_exact_patterns_are_exact
    assert Aegis.path_matches?("/webhooks/stripe", "/webhooks/*")
    assert Aegis.path_matches?("/api", "/api")
    refute Aegis.path_matches?("/api/v2", "/api")
    refute Aegis.path_matches?("/public/webhooks/x", "/webhooks/*")
  end

  def test_client_prefix_truncates_every_form
    assert_equal "10.1.2.0", Aegis.client_prefix("10.1.2.3")
    assert_equal "10.1.2.0", Aegis.client_prefix("10.1.2.3:4431")
    assert_equal "10.1.2.0", Aegis.client_prefix("::ffff:10.1.2.3")
    assert_equal "2001:db8:85a3::", Aegis.client_prefix("2001:db8:85a3:0:0:8a2e:370:7334")
    assert_equal "unknown", Aegis.client_prefix(nil)
    assert_equal "unknown", Aegis.client_prefix("not an address")
  end

  def test_matched_but_not_authorised_to_block_logs
    policy = { default_mode: "block", overrides: [], blocking_rules: %w[sqli-union] }
    xss = Aegis::RULES.find { |r| r.id == "xss-script" }
    assert_equal "log", Aegis.decide(policy, "/x", [xss])[:action]
  end

  def test_an_exempt_rule_does_not_count
    policy = { default_mode: "block", blocking_rules: %w[sqli-union],
               overrides: [{ pattern: "/search", mode: "block", exempt_rules: %w[sqli-union], reason: "r" }] }
    union = Aegis::RULES.find { |r| r.id == "sqli-union" }
    assert_equal "allow", Aegis.decide(policy, "/search", [union])[:action]
  end
end

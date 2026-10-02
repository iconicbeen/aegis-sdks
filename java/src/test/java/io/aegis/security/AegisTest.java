package io.aegis.security;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The Java SDK, exercised through a real HTTP server.
 *
 * <p>Not by calling {@code evaluate} directly: the failure modes that matter
 * are a consumed request body, an exception escaping into the handler chain,
 * and a thread outliving the process, and none of those are visible from a
 * unit call.
 *
 * <p>Run without a test framework, so the SDK has no build-time dependencies
 * either. A failure throws, and the runner reports which assertion.
 */
public final class AegisTest {

  private static int failures = 0;
  private static final String ATTACK = "1' UNION SELECT password FROM users";

  public static void main(String[] args) throws Exception {
    cleanTrafficPasses();
    monitorModeReportsWithoutBlocking();
    percentEncodingDoesNotDefeatDetection();
    blockModeWithNoPolicyActuallyBlocks();
    exemptEndpointPassesTheSameAttack();
    monitorModeCannotBeEscalatedByPolicy();
    theApplicationStillReceivesItsBody();
    anAttackInTheBodyIsDetected();
    anUnreachableControlPlaneDoesNotBreakRequests();
    clientAddressesAreTruncated();
    pathMatchingIsAnchored();
    aRuleNotInTheBlockingListLogsInstead();
    anExemptRuleDoesNotBlock();
    aBrokenApplicationIsNotMasked();
    jsonIsEscapedProperly();

    if (failures > 0) {
      System.out.println(failures + " assertion(s) failed");
      System.exit(1);
    }
    System.out.println("all Java SDK tests passed");
  }

  // ---------------------------------------------------------------------------
  // Harness
  // ---------------------------------------------------------------------------

  /** A control plane stand-in that records what the SDK actually sends. */
  private static final class Collector {
    final HttpServer server;
    final List<String> bodies = new CopyOnWriteArrayList<>();

    Collector() throws IOException {
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.createContext("/", exchange -> {
        bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        byte[] response = "{}".getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
      });
      server.start();
    }

    String url() {
      return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    void close() {
      server.stop(0);
    }
  }

  /** An application behind the filter, echoing its body so a consumed body shows. */
  private static HttpServer application(Aegis.Config config, Aegis.Reporter reporter)
      throws IOException {
    Aegis.ProtectionPolicy policy = Aegis.effectivePolicy(config);
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

    server.createContext("/", exchange -> {
      // The body is read once here and handed to both the firewall and the
      // application, which is what a servlet filter does with a wrapper.
      byte[] body = exchange.getRequestBody().readAllBytes();
      Map<String, String> headers = new HashMap<>();
      exchange.getRequestHeaders()
          .forEach((name, values) -> headers.put(name, values.isEmpty() ? "" : values.get(0)));

      URI uri = exchange.getRequestURI();
      Aegis.RequestView view = Aegis.viewOf(
          exchange.getRequestMethod(),
          uri.getPath(),
          uri.getRawQuery(),
          headers,
          exchange.getRemoteAddress() == null ? "" : exchange.getRemoteAddress().toString(),
          new String(body, StandardCharsets.UTF_8));

      Aegis.Outcome outcome = Aegis.evaluate(config, policy, view);
      if (outcome.event() != null && reporter != null) {
        reporter.add(outcome.event());
      }

      if (outcome.decision() != null && "block".equals(outcome.decision().action())) {
        exchange.getResponseHeaders().add("content-type", "application/json");
        exchange.sendResponseHeaders(403, 0);
        Aegis.writeRejection(exchange.getResponseBody());
        exchange.close();
        return;
      }

      if ("/boom".equals(uri.getPath())) {
        // The application's own failure must not be masked by the firewall.
        throw new IllegalStateException("application failure");
      }

      String echoed = "{\"ok\":true,\"received\":" + Aegis.quote(
          new String(body, StandardCharsets.UTF_8)) + "}";
      byte[] response = echoed.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("content-type", "application/json");
      exchange.sendResponseHeaders(200, response.length);
      exchange.getResponseBody().write(response);
      exchange.close();
    });
    server.start();
    return server;
  }

  private record Response(int status, String body) {}

  private static Response get(HttpServer server, String path) throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path))
        .timeout(Duration.ofSeconds(5))
        .GET()
        .build();
    HttpResponse<String> response =
        HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    return new Response(response.statusCode(), response.body());
  }

  private static Response post(HttpServer server, String path, String body) throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path))
        .header("content-type", "application/json")
        .timeout(Duration.ofSeconds(5))
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    HttpResponse<String> response =
        HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    return new Response(response.statusCode(), response.body());
  }

  private static String encode(String value) {
    // Percent-encoding, not URLEncoder's form encoding. URLEncoder writes a
    // space as "+", and the sqli pattern's [\s\S] happily matches a "+", so a
    // test using it would pass even with decoding removed entirely. Real
    // clients send %20 in a query string, and that is what must be caught.
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static Aegis.Config config(String url, String mode, Aegis.ProtectionPolicy policy) {
    Aegis.Config config = new Aegis.Config();
    config.url = url;
    config.token = "test-token";
    config.appName = "java-test";
    config.mode = mode;
    config.policy = policy;
    config.flushInterval = Duration.ofMillis(300);
    return config;
  }

  // ---------------------------------------------------------------------------
  // Assertions
  // ---------------------------------------------------------------------------

  private static void check(boolean condition, String description) {
    if (!condition) {
      failures++;
      System.out.println("FAIL: " + description);
    }
  }

  private static void equal(Object actual, Object expected, String description) {
    if (!java.util.Objects.equals(actual, expected)) {
      failures++;
      System.out.println("FAIL: " + description + " (expected " + expected + ", got " + actual + ")");
    }
  }

  // ---------------------------------------------------------------------------
  // Tests
  // ---------------------------------------------------------------------------

  private static void cleanTrafficPasses() throws Exception {
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "block", null);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        // A firewall that blocks ordinary traffic gets removed, so the
        // false-positive direction matters as much as the other one.
        for (String path : List.of(
            "/", "/search?q=hello", "/reports?range=30d", "/x?q=deleted+items", "/undelete")) {
          equal(get(app, path).status(), 200, path + " should pass");
        }
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void monitorModeReportsWithoutBlocking() throws Exception {
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "monitor", null);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        // Monitor is the default precisely so that installing the SDK cannot
        // itself cause an outage.
        equal(get(app, "/api?q=" + encode(ATTACK)).status(), 200, "monitor mode must not block");
        Thread.sleep(700);

        check(!collector.bodies.isEmpty(), "monitor mode should still report the attack");
        if (!collector.bodies.isEmpty()) {
          String sent = collector.bodies.get(0);
          check(sent.contains("sqli-union"), "the report should name the rule");
          check(sent.contains("\"blocked\":false"), "monitor mode must record it as not blocked");
          check(sent.toLowerCase().contains("monitor"), "the reason should say why");
        }
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void percentEncodingDoesNotDefeatDetection() throws Exception {
    // The bug found in the Python port: a query string arrives percent-encoded,
    // so %20 defeats every pattern containing a space.
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "block", null);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        equal(get(app, "/api?q=" + encode(ATTACK)).status(), 403,
            "an encoded payload should still be detected");
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void blockModeWithNoPolicyActuallyBlocks() throws Exception {
    // The regression this guards: a default policy carries no blocking rules
    // on purpose, so mode "block" would quietly block nothing.
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "block", null);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        equal(get(app, "/api?q=" + encode(ATTACK)).status(), 403, "block mode should block");
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void exemptEndpointPassesTheSameAttack() throws Exception {
    Aegis.ProtectionPolicy policy = new Aegis.ProtectionPolicy(
        "block",
        List.of(new Aegis.EndpointOverride(
            "/webhooks/*",
            "monitor",
            "Third-party payloads look like attacks and we do not control them.")),
        List.of("sqli-union", "command-injection"));

    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "block", policy);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        equal(get(app, "/api?q=" + encode(ATTACK)).status(), 403, "protected path should block");
        // Same payload, different outcome: that is the point of per-endpoint
        // policy. Without it the only way to stop blocking one misfiring
        // endpoint is to stop blocking everywhere.
        equal(get(app, "/webhooks/stripe?q=" + encode(ATTACK)).status(), 200,
            "exempt path should pass");

        Thread.sleep(700);
        String all = String.join("", collector.bodies);
        check(all.contains("\"path\":\"/api\""), "the blocked request should be reported");
        // The exempt endpoint is still reported, so the attack stays visible.
        check(all.contains("/webhooks/stripe"), "the exempt request should still be reported");
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void monitorModeCannotBeEscalatedByPolicy() throws Exception {
    // Blocking takes two separate opt-ins, and this is the second missing.
    Aegis.ProtectionPolicy policy =
        new Aegis.ProtectionPolicy("block", List.of(), List.of("sqli-union"));
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "monitor", policy);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        equal(get(app, "/api?q=" + encode(ATTACK)).status(), 200,
            "a policy must not escalate monitor mode");
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void theApplicationStillReceivesItsBody() throws Exception {
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "block", null);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        String payload = "{\"name\": \"hello world\"}";
        Response response = post(app, "/submit", payload);
        equal(response.status(), 200, "a clean POST should pass");
        check(response.body().contains("hello world"),
            "the application must still receive its body");
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void anAttackInTheBodyIsDetected() throws Exception {
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "block", null);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        equal(post(app, "/api", "{\"q\":\"" + ATTACK + "\"}").status(), 403,
            "an attack in the body should be blocked");
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void anUnreachableControlPlaneDoesNotBreakRequests() throws Exception {
    List<Exception> errors = new ArrayList<>();
    Aegis.Config config = config("http://127.0.0.1:1", "monitor", null);
    config.onError = errors::add;

    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        // Reporting is best-effort; the request is not.
        equal(get(app, "/api?q=" + encode(ATTACK)).status(), 200,
            "a failed report must not affect the request");
        Thread.sleep(700);
        check(!errors.isEmpty(), "a failed report should surface through onError");
      } finally {
        app.stop(0);
      }
    }
  }

  private static void aBrokenApplicationIsNotMasked() throws Exception {
    // The firewall must not convert an application error into something else,
    // or debugging becomes impossible.
    Collector collector = new Collector();
    Aegis.Config config = config(collector.url(), "monitor", null);
    try (Aegis.Reporter reporter = new Aegis.Reporter(config)) {
      HttpServer app = application(config, reporter);
      try {
        int status = get(app, "/boom").status();
        // The JDK server turns an uncaught handler exception into a dropped
        // connection or a 500; either way it is not a 200.
        check(status != 200, "an application failure must not be reported as success");
      } catch (Exception e) {
        // A dropped connection is also acceptable: the point is that the
        // failure surfaced rather than being swallowed.
        check(true, "application failure surfaced");
      } finally {
        app.stop(0);
      }
    }
    collector.close();
  }

  private static void clientAddressesAreTruncated() {
    // A full client IP is personal data the control plane has no use for.
    equal(Aegis.clientPrefix("192.0.2.44:54321"), "192.0.2.0", "IPv4 with a port");
    equal(Aegis.clientPrefix("192.0.2.44"), "192.0.2.0", "bare IPv4");
    equal(Aegis.clientPrefix("::ffff:192.0.2.44"), "192.0.2.0", "IPv4-mapped IPv6");
    equal(Aegis.clientPrefix(""), "unknown", "empty address");
    equal(Aegis.clientPrefix("2001:db8:85a3::8a2e"), "2001:db8:85a3::", "IPv6");
  }

  private static void pathMatchingIsAnchored() {
    check(Aegis.pathMatches("/webhooks/stripe", "/webhooks/*"), "a glob matches its prefix");
    check(Aegis.pathMatches("/api", "/api"), "an exact pattern matches itself");
    // A prefix that is not a glob must not match by accident.
    check(!Aegis.pathMatches("/api/v2", "/api"), "exact patterns do not match longer paths");
    // And a pattern must not match something merely containing it.
    check(!Aegis.pathMatches("/public/webhooks/x", "/webhooks/*"), "globs are anchored");
  }

  private static void aRuleNotInTheBlockingListLogsInstead() {
    Aegis.ProtectionPolicy policy =
        new Aegis.ProtectionPolicy("block", List.of(), List.of("command-injection"));
    List<Aegis.Rule> matched =
        Aegis.RULES.stream().filter(r -> r.id().equals("sqli-union")).toList();
    Aegis.Decision decision = Aegis.decide(policy, "/api", matched);
    // Matched but not authorised to block: the conservative reading.
    equal(decision.action(), "log", "an unauthorised rule should log");
    check(decision.reason().contains("not in the blocking rule list"),
        "the reason should explain itself");
  }

  private static void anExemptRuleDoesNotBlock() {
    Aegis.ProtectionPolicy policy = new Aegis.ProtectionPolicy(
        "block",
        List.of(new Aegis.EndpointOverride(
            "/import", "block", "Bulk import.", List.of("sqli-union"))),
        List.of("sqli-union"));
    List<Aegis.Rule> matched =
        Aegis.RULES.stream().filter(r -> r.id().equals("sqli-union")).toList();
    equal(Aegis.decide(policy, "/import", matched).action(), "allow",
        "an exempt rule should allow");
  }

  private static void jsonIsEscapedProperly() {
    // A malformed batch is rejected by the control plane, losing every event
    // in it rather than one field.
    Aegis.Event event = new Aegis.Event(
        "2026-01-01T00:00:00Z", "GET", "/x\"quoted\"", "r", "high", "1.2.3.0",
        "agent\nwith\nnewlines", false, "reason with \\ backslash");
    String json = Aegis.toJson("app", List.of(event));
    check(json.contains("\\\"quoted\\\""), "quotes are escaped");
    check(json.contains("\\n"), "newlines are escaped");
    check(!json.contains("\n"), "no raw newline survives into the JSON");
    check(json.contains("\\\\ backslash"), "backslashes are escaped");
  }

  private AegisTest() {}
}

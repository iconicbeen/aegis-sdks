package io.aegis.security;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Aegis in-app firewall for Java servlet applications.
 *
 * <p>A port of the Node, Python and Go SDKs, holding the same four properties,
 * because they are the reason this is safe to put in a request path at all:
 *
 * <ul>
 *   <li>It never blocks unless explicitly configured to.
 *   <li>It never throws into the request path; an error inside the filter
 *       passes the request through rather than returning a 500.
 *   <li>It reports asynchronously, so latency is unaffected.
 *   <li>It holds no unbounded state.
 * </ul>
 *
 * <p>The detection rules are identical to the other SDKs', verified by a shared
 * corpus. Two SDKs that disagree about what an attack looks like produce
 * findings that cannot be compared across services, and the quieter one
 * silently becomes the weakest link.
 *
 * <p>No dependencies beyond the JDK. This sits in the request path of somebody's
 * production application, and every dependency is a supply chain risk a
 * security tool has no business introducing.
 */
public final class Aegis {

  public static final String VERSION = "0.1.0";

  // ---------------------------------------------------------------------------
  // Detection
  // ---------------------------------------------------------------------------

  /** One detection pattern. */
  public record Rule(String id, String severity, Pattern pattern) {}

  /**
   * Deliberately conservative. A false positive here rejects a real user's
   * request, so each pattern targets syntax that has no legitimate reason to
   * appear in a parameter value, rather than merely suspicious words.
   */
  public static final List<Rule> RULES = List.of(
      new Rule(
          "sqli-union",
          "critical",
          // UNION followed by SELECT is not something a search box sends.
          Pattern.compile("\\bunion\\b[\\s\\S]{0,40}\\bselect\\b",
              Pattern.CASE_INSENSITIVE | Pattern.DOTALL)),
      new Rule(
          "sqli-tautology",
          "high",
          // The quote structure is required so that "1=1" in prose does not match.
          Pattern.compile("['\"]\\s*(or|and)\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+",
              Pattern.CASE_INSENSITIVE)),
      new Rule(
          "path-traversal",
          "high",
          Pattern.compile("(\\.\\.[/\\\\]){2,}|%2e%2e[/\\\\%]", Pattern.CASE_INSENSITIVE)),
      new Rule(
          "command-injection",
          "critical",
          // A shell metacharacter immediately followed by a known binary.
          Pattern.compile("[;|&`$]\\s*(cat|curl|wget|nc|bash|sh|python|perl)\\b",
              Pattern.CASE_INSENSITIVE)),
      new Rule(
          "xss-script",
          "high",
          Pattern.compile("<script[\\s>]|javascript:\\s*[a-z]|\\bonerror\\s*=",
              Pattern.CASE_INSENSITIVE)),
      new Rule(
          "ssrf-metadata",
          "critical",
          // The cloud metadata endpoints, which a user parameter never needs.
          Pattern.compile("169\\.254\\.169\\.254|metadata\\.google\\.internal",
              Pattern.CASE_INSENSITIVE)));

  /** Matches every rule against the given inputs. */
  public static List<Rule> inspect(List<String> values) {
    List<Rule> matched = new ArrayList<>();
    for (Rule rule : RULES) {
      for (String value : values) {
        if (value != null && !value.isEmpty() && rule.pattern().matcher(value).find()) {
          matched.add(rule);
          break;
        }
      }
    }
    return matched;
  }

  /** Truncates an address, so the SDK never reports a full client IP. */
  public static String clientPrefix(String address) {
    if (address == null || address.isEmpty()) {
      return "unknown";
    }
    String clean = address.startsWith("::ffff:") ? address.substring(7) : address;
    int lastColon = clean.lastIndexOf(':');
    // An IPv4 address with a port has exactly one colon; an IPv6 address has
    // several, and stripping its last group would corrupt it.
    if (lastColon > 0 && clean.indexOf(':') == lastColon) {
      clean = clean.substring(0, lastColon);
    }

    if (clean.contains(":")) {
      String[] groups = clean.split(":");
      StringBuilder prefix = new StringBuilder();
      for (int i = 0; i < Math.min(3, groups.length); i++) {
        if (i > 0) {
          prefix.append(':');
        }
        prefix.append(groups[i]);
      }
      return prefix + "::";
    }

    String[] octets = clean.split("\\.");
    if (octets.length != 4) {
      return "unknown";
    }
    return octets[0] + "." + octets[1] + "." + octets[2] + ".0";
  }

  /** Percent-decodes, returning the input unchanged if it will not decode. */
  public static String decodeSafely(String value) {
    if (value == null) {
      return "";
    }
    try {
      return java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return value;
    }
  }

  // ---------------------------------------------------------------------------
  // Policy
  // ---------------------------------------------------------------------------

  /** Per-path override. {@code pattern} supports a trailing {@code *} only. */
  public record EndpointOverride(
      String pattern, String mode, String reason, List<String> exemptRules) {

    public EndpointOverride(String pattern, String mode, String reason) {
      this(pattern, mode, reason, List.of());
    }
  }

  /** What happens when a rule matches. */
  public record ProtectionPolicy(
      String defaultMode, List<EndpointOverride> overrides, List<String> blockingRules) {

    public static ProtectionPolicy monitorOnly() {
      return new ProtectionPolicy("monitor", List.of(), List.of());
    }
  }

  /** The outcome for one request, with the reason recorded. */
  public record Decision(String action, String reason, String ruleId) {}

  /** Anchored glob. Only {@code *} is supported, so a pattern cannot backtrack. */
  public static boolean pathMatches(String path, String pattern) {
    if (pattern.endsWith("*")) {
      return path.startsWith(pattern.substring(0, pattern.length() - 1));
    }
    return path.equals(pattern);
  }

  /**
   * Decides what happens to a request that matched rules.
   *
   * <p>Anything uncertain logs rather than blocks, and every decision carries
   * why: an engineer looking at a blocked request at 3am needs to know in
   * seconds whether to disable a rule.
   */
  public static Decision decide(ProtectionPolicy policy, String path, List<Rule> matched) {
    EndpointOverride override = null;
    for (EndpointOverride candidate : policy.overrides()) {
      if (pathMatches(path, candidate.pattern())) {
        override = candidate;
        break;
      }
    }
    String mode = override != null ? override.mode() : policy.defaultMode();

    if ("off".equals(mode)) {
      return new Decision(
          "allow",
          override != null
              ? "Protection is disabled for " + override.pattern() + ": " + override.reason()
              : "Protection is disabled.",
          null);
    }

    List<String> exempt = override != null ? override.exemptRules() : List.of();
    List<Rule> applicable = matched.stream().filter(r -> !exempt.contains(r.id())).toList();
    if (applicable.isEmpty()) {
      return new Decision("allow", "Nothing applicable matched.", null);
    }

    Rule worst = applicable.stream()
        .filter(r -> "critical".equals(r.severity()))
        .findFirst()
        .orElse(applicable.get(0));

    if ("block".equals(mode) && policy.blockingRules().contains(worst.id())) {
      return new Decision(
          "block",
          "Blocked: " + worst.id() + " (" + worst.severity()
              + ") matched and is enabled for blocking.",
          worst.id());
    }
    if ("block".equals(mode)) {
      // Matched, but not a rule the operator allowed to block. Logging is the
      // conservative reading.
      return new Decision(
          "log",
          worst.id() + " (" + worst.severity()
              + ") matched but is not in the blocking rule list.",
          worst.id());
    }
    return new Decision(
        "log",
        worst.id() + " (" + worst.severity()
            + ") matched. Endpoint is in monitor mode, so the request continues.",
        worst.id());
  }

  // ---------------------------------------------------------------------------
  // Reporting
  // ---------------------------------------------------------------------------

  /** One detection, as reported to the control plane. */
  public record Event(
      String at,
      String method,
      String path,
      String ruleId,
      String severity,
      String clientPrefix,
      String userAgent,
      boolean blocked,
      String reason) {}

  /** Configuration for the filter. */
  public static final class Config {
    public String url = "";
    public String token = "";
    public String appName = "app";
    /** Blocking is opt-in, so installing the SDK cannot itself cause an outage. */
    public String mode = "monitor";
    public ProtectionPolicy policy = null;
    public Duration flushInterval = Duration.ofSeconds(30);
    public int maxBodyBytes = 64 * 1024;
    public Consumer<Exception> onError = e -> {};
  }

  /**
   * Batches events and posts them on a timer.
   *
   * <p>Bounded on purpose: the application's memory matters more than these
   * events, so a full queue drops rather than grows, and a failed post is
   * dropped rather than retried forever.
   */
  public static final class Reporter implements AutoCloseable {
    private static final int MAX_QUEUE = 1000;

    private final Config config;
    private final List<Event> queue = new ArrayList<>();
    private final ScheduledExecutorService scheduler;
    private final HttpClient client =
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public Reporter(Config config) {
      this.config = config;
      // A daemon thread never keeps the JVM alive on the SDK's account.
      this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "aegis-reporter");
        thread.setDaemon(true);
        return thread;
      });
      long millis = Math.max(1, config.flushInterval.toMillis());
      scheduler.scheduleAtFixedRate(this::flush, millis, millis, TimeUnit.MILLISECONDS);
    }

    public void add(Event event) {
      synchronized (queue) {
        if (queue.size() < MAX_QUEUE) {
          queue.add(event);
        }
      }
    }

    /** Visible for tests: what is waiting to be sent. */
    public List<Event> pending() {
      synchronized (queue) {
        return List.copyOf(queue);
      }
    }

    public void flush() {
      List<Event> batch;
      synchronized (queue) {
        if (queue.isEmpty()) {
          return;
        }
        batch = List.copyOf(queue);
        queue.clear();
      }
      if (config.url == null || config.url.isEmpty()) {
        return;
      }

      try {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(config.url.replaceAll("/+$", "") + "/api/public/runtime/events"))
            .header("content-type", "application/json")
            .header("authorization", "Bearer " + config.token)
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.ofString(toJson(config.appName, batch)))
            .build();
        client.send(request, HttpResponse.BodyHandlers.discarding());
      } catch (IOException | InterruptedException e) {
        if (e instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        config.onError.accept(e);
      }
    }

    @Override
    public void close() {
      flush();
      scheduler.shutdownNow();
    }
  }

  /**
   * Serialises a batch.
   *
   * <p>Hand-written rather than pulled from a JSON library, because a single
   * dependency in a security SDK is a supply chain risk that outweighs the
   * convenience of not writing thirty lines.
   */
  static String toJson(String app, List<Event> events) {
    StringBuilder json = new StringBuilder();
    json.append("{\"app\":").append(quote(app)).append(",\"events\":[");
    for (int i = 0; i < events.size(); i++) {
      Event e = events.get(i);
      if (i > 0) {
        json.append(',');
      }
      json.append("{\"at\":").append(quote(e.at()))
          .append(",\"method\":").append(quote(e.method()))
          .append(",\"path\":").append(quote(e.path()))
          .append(",\"ruleId\":").append(quote(e.ruleId()))
          .append(",\"severity\":").append(quote(e.severity()))
          .append(",\"clientPrefix\":").append(quote(e.clientPrefix()))
          .append(",\"userAgent\":").append(quote(e.userAgent()))
          .append(",\"blocked\":").append(e.blocked())
          .append(",\"reason\":").append(quote(e.reason()))
          .append('}');
    }
    return json.append("]}").toString();
  }

  static String quote(String value) {
    if (value == null) {
      return "\"\"";
    }
    StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          // Control characters would produce invalid JSON that the control
          // plane rejects, losing the whole batch rather than one field.
          if (c < 0x20) {
            out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    return out.append('"').toString();
  }

  // ---------------------------------------------------------------------------
  // Request evaluation
  // ---------------------------------------------------------------------------

  /**
   * What the filter needs from a request.
   *
   * <p>A small interface rather than a servlet dependency, so this compiles
   * against the JDK alone and works with jakarta.servlet, javax.servlet, or
   * any framework, via a thin adapter the caller writes.
   */
  public interface RequestView {
    String method();

    String path();

    String queryString();

    String header(String name);

    String remoteAddress();

    /** Already-read body, or an empty string. Never consumes a stream. */
    String body();
  }

  /** The decision plus the event to report, if any. */
  public record Outcome(Decision decision, Event event) {}

  /** Evaluates a request. Never throws: an internal error means allow. */
  public static Outcome evaluate(Config config, ProtectionPolicy policy, RequestView request) {
    try {
      String path = request.path() == null ? "/" : request.path();
      String query = request.queryString() == null ? "" : request.queryString();

      // Both the raw and decoded forms. A percent-encoded space defeats every
      // pattern containing one, and a double-encoded payload only makes sense
      // before decoding.
      List<String> values = new ArrayList<>(
          Arrays.asList(path, query, decodeSafely(query), decodeSafely(path)));

      // Headers an attacker controls and applications commonly trust.
      for (String name : List.of("Referer", "X-Forwarded-For", "User-Agent")) {
        String value = request.header(name);
        if (value != null && !value.isEmpty()) {
          values.add(value.length() > 2000 ? value.substring(0, 2000) : value);
        }
      }

      String body = request.body();
      if (body != null && !body.isEmpty()) {
        values.add(body.length() > 10_000 ? body.substring(0, 10_000) : body);
      }

      List<Rule> matched = inspect(values);
      if (matched.isEmpty()) {
        return new Outcome(null, null);
      }

      Decision decision = decide(policy, path, matched);
      Rule worst = matched.stream()
          .filter(r -> "critical".equals(r.severity()))
          .findFirst()
          .orElse(matched.get(0));

      String userAgent = request.header("User-Agent");
      Event event = new Event(
          Instant.now().toString(),
          request.method() == null ? "GET" : request.method(),
          path,
          worst.id(),
          worst.severity(),
          clientPrefix(request.remoteAddress()),
          userAgent == null ? "" : (userAgent.length() > 300 ? userAgent.substring(0, 300) : userAgent),
          "block".equals(decision.action()),
          // Why, recorded at the time. Reconstructing a decision from policy
          // after the fact is guesswork once the policy has changed.
          decision.reason());

      return new Outcome(decision, event);
    } catch (RuntimeException e) {
      // Never throw into the request path.
      config.onError.accept(e);
      return new Outcome(null, null);
    }
  }

  /**
   * Resolves the effective policy from the mode and any supplied policy.
   *
   * <p>A policy can never escalate monitor mode into blocking. That is the
   * second of the two opt-ins blocking requires.
   */
  public static ProtectionPolicy effectivePolicy(Config config) {
    if (!"block".equals(config.mode)) {
      return ProtectionPolicy.monitorOnly();
    }
    if (config.policy != null) {
      return config.policy;
    }
    // Without this, mode "block" would quietly block nothing: a shared default
    // carries no blocking rules on purpose. The caller has already asked for
    // blocking, so every rule the SDK can detect is eligible.
    return new ProtectionPolicy(
        "block", List.of(), RULES.stream().map(Rule::id).toList());
  }

  /** Writes the rejection body. Deliberately terse. */
  public static void writeRejection(OutputStream output) throws IOException {
    // Naming the rule would tell an attacker exactly what to change.
    output.write("{\"error\":\"Request rejected.\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private Aegis() {}

  /** Convenience for adapters that hold headers in a map. */
  public static RequestView viewOf(
      String method,
      String path,
      String queryString,
      Map<String, String> headers,
      String remoteAddress,
      String body) {
    return new RequestView() {
      @Override
      public String method() {
        return method;
      }

      @Override
      public String path() {
        return path;
      }

      @Override
      public String queryString() {
        return queryString;
      }

      @Override
      public String header(String name) {
        if (headers == null) {
          return null;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
          if (entry.getKey().equalsIgnoreCase(name)) {
            return entry.getValue();
          }
        }
        return null;
      }

      @Override
      public String remoteAddress() {
        return remoteAddress;
      }

      @Override
      public String body() {
        return body;
      }
    };
  }
}

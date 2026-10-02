using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Aegis.Security;

namespace Aegis.Security.Tests;

/// <summary>
/// The .NET SDK, exercised through a real HTTP listener.
///
/// Not by calling Evaluate directly: the failure modes that matter are a
/// consumed request body, an exception escaping into the handler chain, and a
/// background task outliving the process, and none of those are visible from a
/// unit call.
///
/// No test framework, so the SDK has no dev dependency either. A failure is
/// printed with the assertion that failed, and the process exits non-zero.
/// </summary>
public static class Program
{
    private static int _failures;
    private const string Attack = "1' UNION SELECT password FROM users";

    public static async Task<int> Main()
    {
        await CleanTrafficPassesAsync().ConfigureAwait(false);
        await MonitorModeReportsWithoutBlockingAsync().ConfigureAwait(false);
        await PercentEncodingDoesNotDefeatDetectionAsync().ConfigureAwait(false);
        await BlockModeWithNoPolicyActuallyBlocksAsync().ConfigureAwait(false);
        await ExemptEndpointPassesTheSameAttackAsync().ConfigureAwait(false);
        await MonitorModeCannotBeEscalatedByPolicyAsync().ConfigureAwait(false);
        await TheApplicationStillReceivesItsBodyAsync().ConfigureAwait(false);
        await AnAttackInTheBodyIsDetectedAsync().ConfigureAwait(false);
        await AnUnreachableControlPlaneDoesNotBreakRequestsAsync().ConfigureAwait(false);

        ClientAddressesAreTruncated();
        PathMatchingIsAnchored();
        ARuleNotInTheBlockingListLogsInstead();
        AnExemptRuleDoesNotBlock();
        JsonIsEscapedProperly();
        APathologicalInputDoesNotHangTheRequestPath();

        if (_failures > 0)
        {
            Console.WriteLine($"{_failures} assertion(s) failed");
            return 1;
        }

        Console.WriteLine("all .NET SDK tests passed");
        return 0;
    }

    // -----------------------------------------------------------------------
    // Assertions
    // -----------------------------------------------------------------------

    private static void Check(bool condition, string description)
    {
        if (!condition)
        {
            _failures++;
            Console.WriteLine($"FAIL: {description}");
        }
    }

    private static void Same<T>(T actual, T expected, string description)
    {
        if (!EqualityComparer<T>.Default.Equals(actual, expected))
        {
            _failures++;
            Console.WriteLine($"FAIL: {description} (expected {expected}, got {actual})");
        }
    }

    // -----------------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------------

    /// <summary>A control plane stand-in that records what the SDK sends.</summary>
    private sealed class Collector : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly CancellationTokenSource _cancellation = new();
        public readonly List<string> Bodies = new();

        public Collector(int port)
        {
            Url = $"http://127.0.0.1:{port}";
            _listener.Prefixes.Add(Url + "/");
            _listener.Start();
            _ = Task.Run(AcceptAsync);
        }

        public string Url { get; }

        private async Task AcceptAsync()
        {
            while (!_cancellation.IsCancellationRequested)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (Exception)
                {
                    return;
                }

                using var reader = new StreamReader(context.Request.InputStream);
                var body = await reader.ReadToEndAsync().ConfigureAwait(false);
                lock (Bodies)
                {
                    Bodies.Add(body);
                }

                var response = Encoding.UTF8.GetBytes("{}");
                context.Response.ContentLength64 = response.Length;
                await context.Response.OutputStream.WriteAsync(response).ConfigureAwait(false);
                context.Response.Close();
            }
        }

        public IReadOnlyList<string> Received()
        {
            lock (Bodies)
            {
                return Bodies.ToList();
            }
        }

        public void Dispose()
        {
            _cancellation.Cancel();
            _listener.Close();
            _cancellation.Dispose();
        }
    }

    /// <summary>An application behind the firewall, echoing its body.</summary>
    private sealed class Application : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly CancellationTokenSource _cancellation = new();
        private readonly Aegis.Config _config;
        private readonly Aegis.ProtectionPolicy _policy;
        private readonly Aegis.Reporter? _reporter;

        public Application(int port, Aegis.Config config, Aegis.Reporter? reporter)
        {
            _config = config;
            _policy = Aegis.EffectivePolicy(config);
            _reporter = reporter;
            Url = $"http://127.0.0.1:{port}";
            _listener.Prefixes.Add(Url + "/");
            _listener.Start();
            _ = Task.Run(AcceptAsync);
        }

        public string Url { get; }

        private async Task AcceptAsync()
        {
            while (!_cancellation.IsCancellationRequested)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (Exception)
                {
                    return;
                }

                // The body is read once and handed to both the firewall and the
                // application, which is what a middleware does with a buffered
                // stream.
                using var reader = new StreamReader(context.Request.InputStream);
                var body = await reader.ReadToEndAsync().ConfigureAwait(false);

                var headers = new Dictionary<string, string>();
                foreach (var key in context.Request.Headers.AllKeys)
                {
                    if (key is not null)
                    {
                        headers[key] = context.Request.Headers[key] ?? string.Empty;
                    }
                }

                var view = new Aegis.RequestView(
                    context.Request.HttpMethod,
                    context.Request.Url?.AbsolutePath ?? "/",
                    // The raw, still-encoded query: what a real server hands
                    // over, and what the decoding step exists for.
                    context.Request.Url?.Query.TrimStart('?') ?? string.Empty,
                    headers,
                    context.Request.RemoteEndPoint?.ToString() ?? string.Empty,
                    body);

                var outcome = Aegis.Evaluate(_config, _policy, view);
                if (outcome.Event is not null)
                {
                    _reporter?.Add(outcome.Event);
                }

                byte[] payload;
                if (outcome.Decision?.Action == "block")
                {
                    context.Response.StatusCode = 403;
                    payload = Encoding.UTF8.GetBytes(Aegis.RejectionBody);
                }
                else
                {
                    context.Response.StatusCode = 200;
                    payload = Encoding.UTF8.GetBytes(
                        "{\"ok\":true,\"received\":" + Aegis.Quote(body) + "}");
                }

                context.Response.ContentType = "application/json";
                context.Response.ContentLength64 = payload.Length;
                await context.Response.OutputStream.WriteAsync(payload).ConfigureAwait(false);
                context.Response.Close();
            }
        }

        public void Dispose()
        {
            _cancellation.Cancel();
            _listener.Close();
            _cancellation.Dispose();
        }
    }

    private static int _nextPort = 8850;

    private static int NextPort() => Interlocked.Increment(ref _nextPort);

    private static Aegis.Config Config(string url, string mode, Aegis.ProtectionPolicy? policy) =>
        new()
        {
            Url = url,
            Token = "test-token",
            AppName = "dotnet-test",
            Mode = mode,
            Policy = policy,
            FlushInterval = TimeSpan.FromMilliseconds(300),
        };

    /// <summary>Percent-encoding, as a real client sends it.</summary>
    private static string Encode(string value) => Uri.EscapeDataString(value);

    private static async Task<(int Status, string Body)> GetAsync(string url)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        using var response = await client.GetAsync(url).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static async Task<(int Status, string Body)> PostAsync(string url, string body)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await client.PostAsync(url, content).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return ((int)response.StatusCode, responseBody);
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    private static async Task CleanTrafficPassesAsync()
    {
        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "block", null);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        // A firewall that blocks ordinary traffic gets removed, so the
        // false-positive direction matters as much as the other one.
        foreach (var path in new[]
                 {
                     "/", "/search?q=hello", "/reports?range=30d",
                     "/x?q=deleted+items", "/undelete",
                 })
        {
            var (status, _) = await GetAsync(app.Url + path).ConfigureAwait(false);
            Same(status, 200, $"{path} should pass");
        }
    }

    private static async Task MonitorModeReportsWithoutBlockingAsync()
    {
        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "monitor", null);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        // Monitor is the default precisely so that installing the SDK cannot
        // itself cause an outage.
        var (status, _) = await GetAsync(app.Url + "/api?q=" + Encode(Attack)).ConfigureAwait(false);
        Same(status, 200, "monitor mode must not block");

        await Task.Delay(900).ConfigureAwait(false);
        var received = string.Join(string.Empty, collector.Received());

        Check(received.Length > 0, "monitor mode should still report the attack");
        Check(received.Contains("sqli-union", StringComparison.Ordinal), "the report names the rule");
        Check(
            received.Contains("\"blocked\":false", StringComparison.Ordinal),
            "monitor mode records it as not blocked");
        Check(
            received.Contains("monitor", StringComparison.OrdinalIgnoreCase),
            "the reason says why it was not blocked");
    }

    private static async Task PercentEncodingDoesNotDefeatDetectionAsync()
    {
        // The bug found in the Python port: a query string arrives
        // percent-encoded, so %20 defeats every pattern containing a space.
        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "block", null);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        var (status, _) = await GetAsync(app.Url + "/api?q=" + Encode(Attack)).ConfigureAwait(false);
        Same(status, 403, "an encoded payload should still be detected");
    }

    private static async Task BlockModeWithNoPolicyActuallyBlocksAsync()
    {
        // The regression this guards: a default policy carries no blocking
        // rules on purpose, so Mode "block" would quietly block nothing.
        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "block", null);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        var (status, body) = await GetAsync(app.Url + "/api?q=" + Encode(Attack))
            .ConfigureAwait(false);
        Same(status, 403, "block mode with no policy should still block");
        // Naming the rule would tell an attacker exactly what to change.
        Check(!body.Contains("sqli-union", StringComparison.Ordinal), "the rejection reveals no rule");
    }

    private static async Task ExemptEndpointPassesTheSameAttackAsync()
    {
        var policy = new Aegis.ProtectionPolicy(
            "block",
            new[]
            {
                new Aegis.EndpointOverride(
                    "/webhooks/*",
                    "monitor",
                    "Third-party payloads look like attacks and we do not control them."),
            },
            new[] { "sqli-union", "command-injection" });

        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "block", policy);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        var (blocked, _) = await GetAsync(app.Url + "/api?q=" + Encode(Attack)).ConfigureAwait(false);
        var (exempt, _) = await GetAsync(app.Url + "/webhooks/stripe?q=" + Encode(Attack))
            .ConfigureAwait(false);

        Same(blocked, 403, "protected path should block");
        // Same payload, different outcome: that is the point of per-endpoint
        // policy. Without it the only way to stop blocking one misfiring
        // endpoint is to stop blocking everywhere.
        Same(exempt, 200, "the exempt endpoint should pass the same attack");

        await Task.Delay(900).ConfigureAwait(false);
        var received = string.Join(string.Empty, collector.Received());
        Check(received.Contains("\"path\":\"/api\"", StringComparison.Ordinal),
            "the blocked request is reported");
        // The exempt endpoint is still reported, so the attack stays visible.
        Check(received.Contains("/webhooks/stripe", StringComparison.Ordinal),
            "the exempt request is still reported");
    }

    private static async Task MonitorModeCannotBeEscalatedByPolicyAsync()
    {
        // Blocking takes two separate opt-ins, and this is the second missing.
        var policy = new Aegis.ProtectionPolicy(
            "block",
            Array.Empty<Aegis.EndpointOverride>(),
            new[] { "sqli-union" });

        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "monitor", policy);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        var (status, _) = await GetAsync(app.Url + "/api?q=" + Encode(Attack)).ConfigureAwait(false);
        Same(status, 200, "a policy must not escalate monitor mode");
    }

    private static async Task TheApplicationStillReceivesItsBodyAsync()
    {
        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "block", null);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        const string payload = "{\"name\": \"hello world\"}";
        var (status, body) = await PostAsync(app.Url + "/submit", payload).ConfigureAwait(false);

        Same(status, 200, "a clean POST should pass");
        Check(
            body.Contains("hello world", StringComparison.Ordinal),
            "the application still receives its body");
    }

    private static async Task AnAttackInTheBodyIsDetectedAsync()
    {
        using var collector = new Collector(NextPort());
        var config = Config(collector.Url, "block", null);
        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        var (status, _) = await PostAsync(app.Url + "/api", "{\"q\":\"" + Attack + "\"}")
            .ConfigureAwait(false);
        Same(status, 403, "an attack in the body should be blocked");
    }

    private static async Task AnUnreachableControlPlaneDoesNotBreakRequestsAsync()
    {
        var errors = new List<Exception>();
        var config = Config("http://127.0.0.1:1", "monitor", null);
        config.OnError = e =>
        {
            lock (errors)
            {
                errors.Add(e);
            }
        };

        using var reporter = new Aegis.Reporter(config);
        using var app = new Application(NextPort(), config, reporter);

        // Reporting is best-effort; the request is not.
        var (status, _) = await GetAsync(app.Url + "/api?q=" + Encode(Attack)).ConfigureAwait(false);
        Same(status, 200, "a failed report must not affect the request");

        await Task.Delay(900).ConfigureAwait(false);
        lock (errors)
        {
            Check(errors.Count > 0, "a failed report should surface through OnError");
        }
    }

    private static void ClientAddressesAreTruncated()
    {
        // A full client IP is personal data the control plane has no use for.
        Same(Aegis.ClientPrefix("192.0.2.44:54321"), "192.0.2.0", "IPv4 with a port");
        Same(Aegis.ClientPrefix("192.0.2.44"), "192.0.2.0", "bare IPv4");
        Same(Aegis.ClientPrefix("::ffff:192.0.2.44"), "192.0.2.0", "IPv4-mapped IPv6");
        Same(Aegis.ClientPrefix(""), "unknown", "an empty address");
        Same(Aegis.ClientPrefix("2001:db8:85a3::8a2e"), "2001:db8:85a3::", "IPv6");
    }

    private static void PathMatchingIsAnchored()
    {
        Check(Aegis.PathMatches("/webhooks/stripe", "/webhooks/*"), "a glob matches its prefix");
        Check(Aegis.PathMatches("/api", "/api"), "an exact pattern matches itself");
        // A prefix that is not a glob must not match by accident.
        Check(!Aegis.PathMatches("/api/v2", "/api"), "exact patterns do not match longer paths");
        // And a pattern must not match something merely containing it.
        Check(!Aegis.PathMatches("/public/webhooks/x", "/webhooks/*"), "globs are anchored");
    }

    private static void ARuleNotInTheBlockingListLogsInstead()
    {
        var policy = new Aegis.ProtectionPolicy(
            "block",
            Array.Empty<Aegis.EndpointOverride>(),
            new[] { "command-injection" });
        var matched = Aegis.Rules.Where(r => r.Id == "sqli-union").ToList();
        var decision = Aegis.Decide(policy, "/api", matched);

        // Matched but not authorised to block: the conservative reading.
        Same(decision.Action, "log", "an unauthorised rule logs rather than blocks");
        Check(
            decision.Reason.Contains("not in the blocking rule list", StringComparison.Ordinal),
            "the reason explains itself");
    }

    private static void AnExemptRuleDoesNotBlock()
    {
        var policy = new Aegis.ProtectionPolicy(
            "block",
            new[]
            {
                new Aegis.EndpointOverride(
                    "/import", "block", "Bulk import.", new[] { "sqli-union" }),
            },
            new[] { "sqli-union" });
        var matched = Aegis.Rules.Where(r => r.Id == "sqli-union").ToList();

        Same(Aegis.Decide(policy, "/import", matched).Action, "allow", "an exempt rule allows");
    }

    private static void JsonIsEscapedProperly()
    {
        // A malformed batch is rejected by the control plane, losing every
        // event in it rather than one field.
        var e = new Aegis.Event(
            "2026-01-01T00:00:00Z", "GET", "/x\"quoted\"", "r", "high", "1.2.3.0",
            "agent\nwith\nnewlines", false, "reason with \\ backslash");
        var json = Aegis.ToJson("app", new[] { e });

        Check(json.Contains("\\\"quoted\\\"", StringComparison.Ordinal), "quotes are escaped");
        Check(json.Contains("\\n", StringComparison.Ordinal), "newlines are escaped");
        Check(!json.Contains('\n'), "no raw newline survives into the JSON");
        Check(json.Contains("\\\\ backslash", StringComparison.Ordinal), "backslashes are escaped");
    }

    private static void APathologicalInputDoesNotHangTheRequestPath()
    {
        // .NET's regex engine backtracks, so a crafted input could otherwise
        // run for an unbounded time inside somebody's request path. Every
        // pattern carries a match timeout for that reason.
        var pathological = new string('a', 50_000) + "!";
        var started = DateTime.UtcNow;
        Aegis.Inspect(new[] { pathological });
        var elapsed = DateTime.UtcNow - started;

        Check(
            elapsed < TimeSpan.FromSeconds(3),
            $"inspection must stay bounded, took {elapsed.TotalMilliseconds:F0}ms");
    }
}

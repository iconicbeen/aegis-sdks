using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Aegis.Security;

/// <summary>
/// Aegis in-app firewall for .NET.
///
/// A port of the Node, Python, Go, Java and PHP SDKs, holding the same four
/// properties, because they are the reason this is safe to put in a request
/// path at all:
///
/// <list type="bullet">
///   <item>It never blocks unless explicitly configured to.</item>
///   <item>It never throws into the request path; an error inside the
///   middleware passes the request through rather than returning a 500.</item>
///   <item>It reports asynchronously, so latency is unaffected.</item>
///   <item>It holds no unbounded state.</item>
/// </list>
///
/// The detection rules are identical to the other SDKs', verified by a shared
/// corpus. Two SDKs that disagree about what an attack looks like produce
/// findings that cannot be compared across services, and the quieter one
/// silently becomes the weakest link.
///
/// No dependencies beyond the base class library. This sits in the request path
/// of somebody's production application, and every dependency is a supply chain
/// risk a security tool has no business introducing.
/// </summary>
public static class Aegis
{
    public const string Version = "0.1.0";

    /// <summary>One detection pattern.</summary>
    public sealed record Rule(string Id, string Severity, Regex Pattern);

    /// <summary>
    /// Deliberately conservative. A false positive here rejects a real user's
    /// request, so each pattern targets syntax that has no legitimate reason to
    /// appear in a parameter value, rather than merely suspicious words.
    ///
    /// Every pattern carries a match timeout. .NET's regex engine backtracks,
    /// so without one a crafted input could make matching run for an
    /// unbounded time inside somebody's request path. A firewall must not be
    /// the thing that takes the service down.
    /// </summary>
    public static readonly IReadOnlyList<Rule> Rules = new List<Rule>
    {
        new(
            "sqli-union",
            "critical",
            // UNION followed by SELECT is not something a search box sends.
            new Regex(
                @"\bunion\b[\s\S]{0,40}\bselect\b",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(100))),
        new(
            "sqli-tautology",
            "high",
            // The quote structure is required so that "1=1" in prose does not match.
            new Regex(
                @"['""]\s*(or|and)\s+['""]?\d+['""]?\s*=\s*['""]?\d+",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(100))),
        new(
            "path-traversal",
            "high",
            new Regex(
                @"(\.\.[/\\]){2,}|%2e%2e[/\\%]",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(100))),
        new(
            "command-injection",
            "critical",
            // A shell metacharacter immediately followed by a known binary.
            new Regex(
                @"[;|&`$]\s*(cat|curl|wget|nc|bash|sh|python|perl)\b",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(100))),
        new(
            "xss-script",
            "high",
            new Regex(
                @"<script[\s>]|javascript:\s*[a-z]|\bonerror\s*=",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(100))),
        new(
            "ssrf-metadata",
            "critical",
            // The cloud metadata endpoints, which a user parameter never needs.
            new Regex(
                @"169\.254\.169\.254|metadata\.google\.internal",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromMilliseconds(100))),
    };

    /// <summary>Returns the rules matching any of the given inputs.</summary>
    public static List<Rule> Inspect(IEnumerable<string?> values)
    {
        var candidates = values.Where(v => !string.IsNullOrEmpty(v)).ToList();
        var matched = new List<Rule>();

        foreach (var rule in Rules)
        {
            foreach (var value in candidates)
            {
                try
                {
                    if (rule.Pattern.IsMatch(value!))
                    {
                        matched.Add(rule);
                        break;
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                    // A pattern that timed out has told us something: the input
                    // is pathological. Treating it as a match would be a false
                    // positive on a real user, so it is skipped and the other
                    // rules still run.
                }
            }
        }

        return matched;
    }

    /// <summary>Truncates an address, so the SDK never reports a full client IP.</summary>
    public static string ClientPrefix(string? address)
    {
        if (string.IsNullOrEmpty(address))
        {
            return "unknown";
        }

        var clean = address!.StartsWith("::ffff:", StringComparison.Ordinal)
            ? address[7..]
            : address;

        // An IPv4 address with a port has exactly one colon; an IPv6 address
        // has several, and stripping its last group would corrupt it.
        var firstColon = clean.IndexOf(':');
        if (firstColon > 0 && firstColon == clean.LastIndexOf(':'))
        {
            clean = clean[..firstColon];
        }

        if (clean.Contains(':'))
        {
            var groups = clean.Split(':').Take(3);
            return string.Join(":", groups) + "::";
        }

        var octets = clean.Split('.');
        return octets.Length != 4
            ? "unknown"
            : $"{octets[0]}.{octets[1]}.{octets[2]}.0";
    }

    /// <summary>Percent-decodes, returning the input unchanged if it will not decode.</summary>
    public static string DecodeSafely(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        try
        {
            return Uri.UnescapeDataString(value!.Replace("+", " "));
        }
        catch (UriFormatException)
        {
            return value!;
        }
    }

    /// <summary>Per-path override. <c>Pattern</c> supports a trailing <c>*</c> only.</summary>
    public sealed record EndpointOverride(
        string Pattern,
        string Mode,
        string Reason,
        IReadOnlyList<string>? ExemptRules = null);

    /// <summary>What happens when a rule matches.</summary>
    public sealed record ProtectionPolicy(
        string DefaultMode,
        IReadOnlyList<EndpointOverride> Overrides,
        IReadOnlyList<string> BlockingRules)
    {
        public static ProtectionPolicy MonitorOnly() =>
            new("monitor", Array.Empty<EndpointOverride>(), Array.Empty<string>());
    }

    /// <summary>The outcome for one request, with the reason recorded.</summary>
    public sealed record Decision(string Action, string Reason, string? RuleId);

    /// <summary>Anchored glob. Only <c>*</c> is supported, so a pattern cannot backtrack.</summary>
    public static bool PathMatches(string path, string pattern) =>
        pattern.EndsWith('*')
            ? path.StartsWith(pattern[..^1], StringComparison.Ordinal)
            : string.Equals(path, pattern, StringComparison.Ordinal);

    /// <summary>
    /// Decides what happens to a request that matched rules.
    ///
    /// Anything uncertain logs rather than blocks, and every decision carries
    /// why: an engineer looking at a blocked request at 3am needs to know in
    /// seconds whether to disable a rule.
    /// </summary>
    public static Decision Decide(ProtectionPolicy policy, string path, IReadOnlyList<Rule> matched)
    {
        var over = policy.Overrides.FirstOrDefault(o => PathMatches(path, o.Pattern));
        var mode = over?.Mode ?? policy.DefaultMode;

        if (mode == "off")
        {
            return new Decision(
                "allow",
                over is not null
                    ? $"Protection is disabled for {over.Pattern}: {over.Reason}"
                    : "Protection is disabled.",
                null);
        }

        var exempt = over?.ExemptRules ?? Array.Empty<string>();
        var applicable = matched.Where(r => !exempt.Contains(r.Id)).ToList();
        if (applicable.Count == 0)
        {
            return new Decision("allow", "Nothing applicable matched.", null);
        }

        var worst = applicable.FirstOrDefault(r => r.Severity == "critical") ?? applicable[0];

        if (mode == "block" && policy.BlockingRules.Contains(worst.Id))
        {
            return new Decision(
                "block",
                $"Blocked: {worst.Id} ({worst.Severity}) matched and is enabled for blocking.",
                worst.Id);
        }

        if (mode == "block")
        {
            // Matched, but not a rule the operator allowed to block. Logging is
            // the conservative reading.
            return new Decision(
                "log",
                $"{worst.Id} ({worst.Severity}) matched but is not in the blocking rule list.",
                worst.Id);
        }

        return new Decision(
            "log",
            $"{worst.Id} ({worst.Severity}) matched. Endpoint is in monitor mode, so the request continues.",
            worst.Id);
    }

    /// <summary>One detection, as reported to the control plane.</summary>
    public sealed record Event(
        string At,
        string Method,
        string Path,
        string RuleId,
        string Severity,
        string ClientPrefix,
        string UserAgent,
        bool Blocked,
        string Reason);

    /// <summary>Configuration for the middleware.</summary>
    public sealed class Config
    {
        public string Url { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public string AppName { get; set; } = "app";

        /// <summary>Blocking is opt-in, so installing the SDK cannot itself cause an outage.</summary>
        public string Mode { get; set; } = "monitor";

        public ProtectionPolicy? Policy { get; set; }
        public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(30);
        public int MaxBodyBytes { get; set; } = 64 * 1024;
        public Action<Exception> OnError { get; set; } = _ => { };
    }

    /// <summary>
    /// Resolves the effective policy from the mode and any supplied policy.
    ///
    /// A policy can never escalate monitor mode into blocking. That is the
    /// second of the two opt-ins blocking requires.
    /// </summary>
    public static ProtectionPolicy EffectivePolicy(Config config)
    {
        if (config.Mode != "block")
        {
            return ProtectionPolicy.MonitorOnly();
        }

        if (config.Policy is not null)
        {
            return config.Policy;
        }

        // Without this, Mode "block" would quietly block nothing: a shared
        // default carries no blocking rules on purpose. The caller has already
        // asked for blocking, so every rule the SDK can detect is eligible.
        return new ProtectionPolicy(
            "block",
            Array.Empty<EndpointOverride>(),
            Rules.Select(r => r.Id).ToList());
    }

    /// <summary>What the middleware needs from a request.</summary>
    public sealed record RequestView(
        string Method,
        string Path,
        string QueryString,
        IReadOnlyDictionary<string, string> Headers,
        string RemoteAddress,
        string Body)
    {
        public string? Header(string name) =>
            Headers.FirstOrDefault(h =>
                string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value;
    }

    /// <summary>The decision plus the event to report, if any.</summary>
    public sealed record Outcome(Decision? Decision, Event? Event);

    /// <summary>Evaluates a request. Never throws: an internal error means allow.</summary>
    public static Outcome Evaluate(Config config, ProtectionPolicy policy, RequestView request)
    {
        try
        {
            var path = string.IsNullOrEmpty(request.Path) ? "/" : request.Path;
            var query = request.QueryString ?? string.Empty;

            // Both the raw and decoded forms. A percent-encoded space defeats
            // every pattern containing one, and a double-encoded payload only
            // makes sense before decoding.
            var values = new List<string?>
            {
                path,
                query,
                DecodeSafely(query),
                DecodeSafely(path),
            };

            // Headers an attacker controls and applications commonly trust.
            foreach (var name in new[] { "Referer", "X-Forwarded-For", "User-Agent" })
            {
                var value = request.Header(name);
                if (!string.IsNullOrEmpty(value))
                {
                    values.Add(value!.Length > 2000 ? value[..2000] : value);
                }
            }

            if (!string.IsNullOrEmpty(request.Body))
            {
                values.Add(request.Body.Length > 10_000 ? request.Body[..10_000] : request.Body);
            }

            var matched = Inspect(values);
            if (matched.Count == 0)
            {
                return new Outcome(null, null);
            }

            var decision = Decide(policy, path, matched);
            var worst = matched.FirstOrDefault(r => r.Severity == "critical") ?? matched[0];
            var userAgent = request.Header("User-Agent") ?? string.Empty;

            return new Outcome(
                decision,
                new Event(
                    DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
                    string.IsNullOrEmpty(request.Method) ? "GET" : request.Method,
                    path,
                    worst.Id,
                    worst.Severity,
                    ClientPrefix(request.RemoteAddress),
                    userAgent.Length > 300 ? userAgent[..300] : userAgent,
                    decision.Action == "block",
                    // Why, recorded at the time. Reconstructing a decision from
                    // policy after the fact is guesswork once it has changed.
                    decision.Reason));
        }
        catch (Exception e)
        {
            // Never throw into the request path.
            config.OnError(e);
            return new Outcome(null, null);
        }
    }

    /// <summary>
    /// Batches events and posts them on a timer.
    ///
    /// Bounded on purpose: the application's memory matters more than these
    /// events, so a full queue drops rather than grows, and a failed post is
    /// dropped rather than retried forever.
    /// </summary>
    public sealed class Reporter : IDisposable
    {
        private const int MaxQueue = 1000;

        private readonly Config _config;
        private readonly List<Event> _queue = new();
        private readonly HttpClient _client = new() { Timeout = TimeSpan.FromSeconds(10) };
        private readonly CancellationTokenSource _cancellation = new();
        private readonly Task _loop;

        public Reporter(Config config)
        {
            _config = config;
            _loop = Task.Run(LoopAsync);
        }

        public void Add(Event e)
        {
            lock (_queue)
            {
                if (_queue.Count < MaxQueue)
                {
                    _queue.Add(e);
                }
            }
        }

        /// <summary>Visible for tests: what is waiting to be sent.</summary>
        public IReadOnlyList<Event> Pending()
        {
            lock (_queue)
            {
                return _queue.ToList();
            }
        }

        private async Task LoopAsync()
        {
            while (!_cancellation.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_config.FlushInterval, _cancellation.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                await FlushAsync().ConfigureAwait(false);
            }
        }

        public async Task FlushAsync()
        {
            List<Event> batch;
            lock (_queue)
            {
                if (_queue.Count == 0)
                {
                    return;
                }

                batch = _queue.ToList();
                _queue.Clear();
            }

            if (string.IsNullOrEmpty(_config.Url))
            {
                return;
            }

            try
            {
                var content = new StringContent(
                    ToJson(_config.AppName, batch),
                    Encoding.UTF8,
                    "application/json");
                var request = new HttpRequestMessage(
                    HttpMethod.Post,
                    _config.Url.TrimEnd('/') + "/api/public/runtime/events")
                {
                    Content = content,
                };
                request.Headers.TryAddWithoutValidation("authorization", "Bearer " + _config.Token);

                using var response = await _client.SendAsync(request).ConfigureAwait(false);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
            {
                _config.OnError(e);
            }
        }

        public void Dispose()
        {
            FlushAsync().GetAwaiter().GetResult();
            _cancellation.Cancel();
            try
            {
                _loop.Wait(TimeSpan.FromSeconds(2));
            }
            catch (AggregateException)
            {
                // The loop was cancelled, which is the intent.
            }

            _cancellation.Dispose();
            _client.Dispose();
        }
    }

    /// <summary>
    /// Serialises a batch.
    ///
    /// Hand-written rather than pulled from a JSON library, so the SDK depends
    /// on nothing outside the base class library.
    /// </summary>
    public static string ToJson(string app, IReadOnlyList<Event> events)
    {
        var json = new StringBuilder();
        json.Append("{\"app\":").Append(Quote(app)).Append(",\"events\":[");

        for (var i = 0; i < events.Count; i++)
        {
            var e = events[i];
            if (i > 0)
            {
                json.Append(',');
            }

            json.Append("{\"at\":").Append(Quote(e.At))
                .Append(",\"method\":").Append(Quote(e.Method))
                .Append(",\"path\":").Append(Quote(e.Path))
                .Append(",\"ruleId\":").Append(Quote(e.RuleId))
                .Append(",\"severity\":").Append(Quote(e.Severity))
                .Append(",\"clientPrefix\":").Append(Quote(e.ClientPrefix))
                .Append(",\"userAgent\":").Append(Quote(e.UserAgent))
                .Append(",\"blocked\":").Append(e.Blocked ? "true" : "false")
                .Append(",\"reason\":").Append(Quote(e.Reason))
                .Append('}');
        }

        return json.Append("]}").ToString();
    }

    public static string Quote(string? value)
    {
        if (value is null)
        {
            return "\"\"";
        }

        var output = new StringBuilder("\"");
        foreach (var c in value)
        {
            switch (c)
            {
                case '"':
                    output.Append("\\\"");
                    break;
                case '\\':
                    output.Append("\\\\");
                    break;
                case '\n':
                    output.Append("\\n");
                    break;
                case '\r':
                    output.Append("\\r");
                    break;
                case '\t':
                    output.Append("\\t");
                    break;
                default:
                    // Control characters would produce invalid JSON that the
                    // control plane rejects, losing the whole batch rather
                    // than one field.
                    if (c < 0x20)
                    {
                        output.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:x4}");
                    }
                    else
                    {
                        output.Append(c);
                    }

                    break;
            }
        }

        return output.Append('"').ToString();
    }

    /// <summary>The rejection body. Deliberately terse.</summary>
    // Naming the rule would tell an attacker exactly what to change.
    public const string RejectionBody = "{\"error\":\"Request rejected.\"}";
}

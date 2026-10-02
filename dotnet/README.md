# Aegis for .NET

In-app firewall for ASP.NET Core, or anything that can describe a request.

```csharp
var config = new Aegis.Config {
    Url = "https://aegis.example.com",
    Token = Environment.GetEnvironmentVariable("AEGIS_TOKEN")!,
    AppName = "checkout",
};
var reporter = new Aegis.Reporter(config);
var policy = Aegis.EffectivePolicy(config);

app.Use(async (context, next) => {
    var view = new Aegis.RequestView(
        context.Request.Method,
        context.Request.Path,
        context.Request.QueryString.Value?.TrimStart('?') ?? "",
        context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
        context.Connection.RemoteIpAddress?.ToString() ?? "",
        body);

    var outcome = Aegis.Evaluate(config, policy, view);
    if (outcome.Event is not null) reporter.Add(outcome.Event);

    if (outcome.Decision?.Action == "block") {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync(Aegis.RejectionBody);
        return;
    }
    await next();
});
```

That reports what it sees and interferes with nothing.

## Blocking

```csharp
config.Mode = "block";
config.Policy = new Aegis.ProtectionPolicy(
    "block",
    new[] { new Aegis.EndpointOverride(
        "/webhooks/*", "monitor",
        "Third-party payloads look like attacks and we do not control them.") },
    new[] { "sqli-union", "command-injection" });
```

A policy can never escalate `Mode = "monitor"` into blocking.

## What it guarantees

- It never blocks unless explicitly configured to.
- It never throws into your request path.
- Every pattern carries a 100ms match timeout. .NET's regex engine backtracks,
  so without one a crafted input could make matching run for an unbounded time
  in your request path. A firewall must not be the thing that takes the service
  down.
- It reports on a background task, so latency is unaffected.
- It holds no unbounded state: the event queue is capped.
- It never sends a full client IP address, only a truncated network prefix.
- It has no `PackageReference` at all.

## Testing

```sh
dotnet run --project tests/Aegis.Security.Tests.csproj
```

The tests run a real `HttpListener`, so blocking, body handling and reporting
are exercised over real HTTP.

## Parity

All six SDKs are tested against a shared corpus and must reach identical
verdicts.

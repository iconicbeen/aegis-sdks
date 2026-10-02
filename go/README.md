# Aegis for Go

In-app firewall middleware for any `http.Handler`.

```go
mw := aegis.New(aegis.Config{
    URL:     "https://aegis.example.com",
    Token:   os.Getenv("AEGIS_TOKEN"),
    AppName: "checkout",
})
defer mw.Close()

http.ListenAndServe(":8080", mw.Handler(mux))
```

That reports what it sees and interferes with nothing. Installing it cannot
cause an outage.

## Blocking

Blocking takes two separate opt-ins, because a false positive here rejects a
real customer's request:

```go
mw := aegis.New(aegis.Config{
    URL: ..., Token: ..., AppName: "checkout",
    Mode: "block",
    Policy: &aegis.ProtectionPolicy{
        DefaultMode:   "block",
        BlockingRules: []string{"sqli-union", "command-injection"},
        Overrides: []aegis.EndpointOverride{{
            Pattern: "/webhooks/*",
            Mode:    "monitor",
            Reason:  "Third-party payloads look like attacks and we do not control them.",
        }},
    },
})
```

A policy can never escalate `Mode: "monitor"` into blocking. Per-endpoint
overrides exist so that one misfiring endpoint can be exempted without
disabling protection everywhere, which is otherwise how a firewall ends up
turned off entirely.

## What it guarantees

- It never blocks unless explicitly configured to.
- It never panics into your request path. A panic inside the middleware is
  recovered and the request continues. A panic in _your_ handler still
  propagates, so your own error handling is unaffected.
- It reports asynchronously on a background goroutine, so latency is
  unaffected.
- It holds no unbounded state: the event queue is capped and drops rather than
  grows.
- It never sends a full client IP address, only a truncated network prefix.
- It has no dependencies outside the standard library.

The patterns use RE2, which has no backtracking, so a crafted input cannot make
matching run in exponential time. A firewall must not be the thing that takes
the service down.

## Request bodies

The middleware reads and restores `r.Body`, so your handler still receives it.
Inspection is capped at 64 KB by default; the handler always receives the whole
request regardless.

## Parity with the other SDKs

Node, Python and Go are tested against a shared corpus of attacks and ordinary
traffic and must reach identical verdicts. An estate running more than one
should not find the same request blocked on one service and waved through on
another.

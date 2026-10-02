# Aegis for Python

In-app firewall middleware for WSGI applications: Flask, Django, Pyramid, or
anything else that speaks WSGI.

```python
from aegis_sarl import AegisWSGI

app.wsgi_app = AegisWSGI(
    app.wsgi_app,
    url="https://aegis.example.com",
    token=os.environ["AEGIS_TOKEN"],
    app_name="checkout",
)
```

That reports what it sees and interferes with nothing. Installing it cannot
cause an outage.

## Blocking

Blocking takes two separate opt-ins, because a false positive here rejects a
real customer's request:

```python
from aegis_sarl import AegisWSGI, ProtectionPolicy, EndpointOverride

app.wsgi_app = AegisWSGI(
    app.wsgi_app,
    url=..., token=..., app_name="checkout",
    mode="block",
    policy=ProtectionPolicy(
        default_mode="block",
        blocking_rules=("sqli-union", "command-injection"),
        overrides=(
            EndpointOverride(
                pattern="/webhooks/*",
                mode="monitor",
                reason="Third-party payloads look like attacks and we do not control them.",
            ),
        ),
    ),
)
```

A policy can never escalate `mode="monitor"` into blocking. Per-endpoint
overrides exist so that one misfiring endpoint can be exempted without
disabling protection everywhere, which is otherwise how a firewall ends up
turned off entirely.

## What it guarantees

- It never blocks unless explicitly configured to.
- It never raises into your request path. An error inside the middleware
  passes the request through rather than returning a 500.
- It reports asynchronously on a background thread, so latency is unaffected.
- It holds no unbounded state: the event queue is capped and drops rather than
  grows.
- It never sends a full client IP address, only a truncated network prefix.
- It has no runtime dependencies.

## Request bodies

The middleware reads and restores the WSGI input stream, so your application
still receives its body. Inspection is capped at 64 KB by default; the
application always receives the whole request regardless.

## Parity with the Node SDK

Both SDKs are tested against a shared corpus of attacks and ordinary traffic,
and must reach identical verdicts. An estate running both should not find the
same request blocked on one service and waved through on another.

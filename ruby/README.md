# Aegis for Ruby

In-app firewall middleware for Rack applications: Rails, Sinatra, Hanami, or
anything else that speaks Rack.

```ruby
# config/application.rb (Rails) or config.ru
require "aegis_sarl"

use Aegis::Middleware,
    url: "https://aegis.example.com",
    token: ENV.fetch("AEGIS_TOKEN"),
    app_name: "checkout"
```

That reports what it sees and interferes with nothing. Installing it cannot
cause an outage.

## Blocking

Blocking takes two separate opt-ins, because a false positive here rejects a
real customer's request:

```ruby
use Aegis::Middleware,
    url: ..., token: ..., app_name: "checkout",
    mode: "block",
    policy: {
      default_mode: "block",
      blocking_rules: %w[sqli-union command-injection],
      overrides: [
        { pattern: "/webhooks/*", mode: "monitor",
          reason: "Third-party payloads look like attacks and we do not control them." },
      ],
    }
```

A policy can never escalate `mode: "monitor"` into blocking.

## What it guarantees

- It never blocks unless explicitly configured to.
- It never raises into your request path. An error inside the middleware
  passes the request through rather than returning a 500.
- It reports on a background thread, so latency is unaffected.
- It holds no unbounded state: the event queue is capped at 1000 and drops.
- It never sends a full client IP address, only a truncated network prefix.
- It has no runtime dependencies, not even the `rack` gem.
- The request body the application reads is the one the client sent. Rack 3
  does not require `rack.input` to be rewindable, and under WEBrick reading it
  left the application an empty body; the middleware hands the bytes back
  rather than relying on `rewind`.

## Verified

`test_aegis.rb` runs the middleware behind WEBrick over real HTTP, with a
second server collecting the reports, under Ruby 4.0
(the platform test `sdk-ruby-e2e.test.ts`). The detection rules are checked
against the other six SDKs on a shared corpus
(the platform test `sdk-parity-e2e.test.ts`).

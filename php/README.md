# Aegis for PHP

In-app firewall for PHP applications.

```php
require 'src/Aegis.php';

\Aegis\Aegis::protect([
    'url' => 'https://aegis.example.com',
    'token' => getenv('AEGIS_TOKEN'),
    'app_name' => 'checkout',
]);
```

Call it as early in the request as possible. That reports what it sees and
interferes with nothing. Installing it cannot cause an outage.

## Blocking

```php
\Aegis\Aegis::protect([
    'url' => ..., 'token' => ..., 'app_name' => 'checkout',
    'mode' => 'block',
    'policy' => [
        'default_mode' => 'block',
        'blocking_rules' => ['sqli-union', 'command-injection'],
        'overrides' => [[
            'pattern' => '/webhooks/*',
            'mode' => 'monitor',
            'reason' => 'Third-party payloads look like attacks and we do not control them.',
            'exempt_rules' => [],
        ]],
    ],
]);
```

A policy can never escalate `'mode' => 'monitor'` into blocking.

## How reporting works in PHP

There is no long-lived process to hold a background thread, so events are
flushed on request shutdown, **after the response has been sent**. The user
never waits for the control plane. That is the same guarantee the other SDKs
give with a background thread, reached differently because PHP's execution
model is different.

## What it guarantees

- It never blocks unless explicitly configured to.
- It never throws into your request path.
- Reporting happens after the response, so latency is unaffected.
- It holds no unbounded state: the event queue is capped.
- It never sends a full client IP address, only a truncated network prefix.
- It has no dependencies.

## Testing

```sh
php test_aegis.php
```

The tests run PHP's own built-in server, so blocking, body handling and
reporting are exercised over real HTTP rather than by calling a function.

## Parity

All six SDKs are tested against a shared corpus and must reach identical
verdicts.

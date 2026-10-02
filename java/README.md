# Aegis for Java

In-app firewall for servlet applications, or anything that can describe a
request.

```java
Aegis.Config config = new Aegis.Config();
config.url = "https://aegis.example.com";
config.token = System.getenv("AEGIS_TOKEN");
config.appName = "checkout";

Aegis.Reporter reporter = new Aegis.Reporter(config);
Aegis.ProtectionPolicy policy = Aegis.effectivePolicy(config);

// In your filter:
Aegis.Outcome outcome = Aegis.evaluate(config, policy, view);
if (outcome.event() != null) reporter.add(outcome.event());
if (outcome.decision() != null && "block".equals(outcome.decision().action())) {
    response.setStatus(403);
    Aegis.writeRejection(response.getOutputStream());
    return;
}
chain.doFilter(request, response);
```

That reports what it sees and interferes with nothing. Installing it cannot
cause an outage.

## Why an adapter rather than a servlet filter

`Aegis.RequestView` is a four-method interface, and `Aegis.viewOf(...)` builds
one from plain values. That keeps this compiling against the JDK alone, so it
works with `jakarta.servlet`, the older `javax.servlet`, Spring, or a bare
`HttpServer`, without pulling a servlet API into your dependency tree to suit
whichever one you are not using.

## Blocking

```java
config.mode = "block";
config.policy = new Aegis.ProtectionPolicy(
    "block",
    List.of(new Aegis.EndpointOverride(
        "/webhooks/*", "monitor",
        "Third-party payloads look like attacks and we do not control them.")),
    List.of("sqli-union", "command-injection"));
```

A policy can never escalate `mode = "monitor"` into blocking. Per-endpoint
overrides exist so one misfiring endpoint can be exempted without disabling
protection everywhere, which is otherwise how a firewall ends up turned off.

## What it guarantees

- It never blocks unless explicitly configured to.
- It never throws into your request path.
- It reports on a daemon thread, so latency is unaffected and the JVM is never
  held open on the SDK's account.
- It holds no unbounded state: the event queue is capped and drops rather than
  grows.
- It never sends a full client IP address, only a truncated network prefix.
- It has no dependencies outside the JDK.

## Building

```sh
javac -d build/classes src/main/java/io/aegis/security/Aegis.java
java -cp build/classes io.aegis.security.AegisTest   # after compiling the test too
```

## Parity

All six SDKs are tested against a shared corpus of attacks and ordinary traffic
and must reach identical verdicts. An estate running more than one should not
find the same request blocked on one service and waved through on another.

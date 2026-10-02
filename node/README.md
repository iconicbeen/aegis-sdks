# @aegis-sarl/node

In-app firewall middleware for Node, part of [Aegis](https://app.aegis.sarl).
It inspects each request, reports what it saw to your Aegis organisation, and
blocks only when you tell it to.

```sh
npm install @aegis-sarl/node
```

```js
import express from "express";
import { aegis } from "@aegis-sarl/node";

const app = express();

// Reports what it sees and interferes with nothing.
app.use(
  aegis({
    url: "https://app.aegis.sarl",
    token: process.env.AEGIS_AGENT_TOKEN,
    appName: "checkout-api",
  }),
);
```

The token comes from Aegis: open Runtime, enter a service name and choose
Register agent. It is shown once.

## Blocking

Monitor mode is the default, so installing the SDK cannot cause an outage. To
block, set `mode: "block"`. A `policy` can then exempt endpoints whose traffic
legitimately looks like an attack, such as webhooks:

```js
import { aegis, DEFAULT_PROTECTION_POLICY, RUNTIME_RULES } from "@aegis-sarl/node";

aegis({
  url: "https://app.aegis.sarl",
  token: process.env.AEGIS_AGENT_TOKEN,
  appName: "checkout-api",
  mode: "block",
  policy: {
    ...DEFAULT_PROTECTION_POLICY,
    // The default policy is monitor-only; both of these are needed to block.
    defaultMode: "block",
    blockingRules: RUNTIME_RULES.map((rule) => rule.id),
    overrides: [
      {
        pattern: "/webhooks/*",
        mode: "monitor",
        reason: "Third-party payloads look like attacks and we do not control them.",
      },
    ],
  },
});
```

## Options

| Option                 | Purpose                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| `url`                  | Aegis base URL                                                          |
| `token`                | Agent token                                                             |
| `appName`              | How this application appears in Aegis                                   |
| `mode`                 | `"monitor"` (default) or `"block"`                                      |
| `policy`               | Per-endpoint protection policy, consulted only in block mode            |
| `exclude`              | Paths never inspected, such as health checks                            |
| `flushIntervalSeconds` | Seconds between report flushes                                          |
| `onError`              | Called instead of throwing                                              |
| `challengeSecret`      | Enables proof-of-work challenges instead of outright rate-limit refusal |

## Guarantees

- It never throws into your request path. An error inside the firewall lets
  the request through.
- Reporting is asynchronous, so it adds no latency to responses.
- It holds no unbounded state.
- No runtime dependencies.

Source: [github.com/iconicbeen/aegis-sdks](https://github.com/iconicbeen/aegis-sdks/tree/main/node).
MIT licensed.

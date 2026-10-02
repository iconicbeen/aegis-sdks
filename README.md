# Aegis SDKs

In-app firewall middleware for [Aegis](https://app.aegis.sarl). Each SDK
inspects incoming requests, reports what it saw to your Aegis organisation,
and blocks only when you tell it to. They start in monitor mode: nothing is
refused until you change that.

| Language | Install                                         | Directory         |
| -------- | ----------------------------------------------- | ----------------- |
| Node     | `npm install @aegis-sarl/node`                  | [node/](node)     |
| Python   | `pip install aegis-sarl`                        | [python/](python) |
| Go       | `go get github.com/iconicbeen/aegis-sdks/go`    | [go/](go)         |
| Java     | `implementation("sarl.aegis:aegis-sarl:0.1.0")` | [java/](java)     |
| PHP      | `composer require aegis-sarl/sdk`               | [php/](php)       |
| .NET     | `dotnet add package AegisSarl.Security`         | [dotnet/](dotnet) |
| Ruby     | `gem install aegis-sarl`                        | [ruby/](ruby)     |

Each directory's README shows how to wire the middleware into that
language's frameworks. You need an agent token: in Aegis, open Runtime, enter
a service name and choose Register agent. The token is shown once.

## Design

- **No runtime dependencies.** These sit in your request path, and every
  dependency is a supply-chain risk a security tool has no business adding.
- **The same rules in every language.** All seven SDKs are checked against one
  shared detection corpus, so a request blocked in Python is blocked in Go.
- **Monitor first.** Blocking is opt-in per application and per endpoint, so
  turning Aegis on cannot take your site down.

## Source

This repository is generated from the Aegis platform repository, where the
SDKs are tested against the real server. Issues and pull requests are welcome
here; accepted changes are applied upstream and mirrored back.

## License

MIT

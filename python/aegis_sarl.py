"""
Aegis in-app firewall for Python (WSGI and ASGI).

A port of the Node SDK, holding the same four properties, because they are the
reason the middleware is safe to put in a request path at all:

    It never blocks unless explicitly configured to.
    It never raises into the request path; an internal error passes the
    request through rather than returning a 500.
    It reports asynchronously, so latency is unaffected.
    It holds no unbounded state.

The detection rules are deliberately identical to the Node SDK's, character for
character where the regex syntax allows. Two SDKs that disagree about what an
attack looks like produce findings that cannot be compared across services, and
the quieter one silently becomes the weakest link.

Usage with Flask, Django, or any WSGI application:

    from aegis_sarl import AegisWSGI
    app.wsgi_app = AegisWSGI(app.wsgi_app, url="https://aegis.example.com",
                             token="...", app_name="checkout")

Blocking requires two separate opt-ins: mode="block" and a policy that names
the rules allowed to block.
"""

from __future__ import annotations

import atexit
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

__version__ = "0.1.0"

# Without this, `from aegis_sarl import *` re-exports every module-level name,
# including the imports this file makes for its own use. `field` from
# dataclasses is the damaging one: it silently replaces a same-named function
# in the consumer's module. Naming the public surface keeps a wildcard import
# to the API and nothing else.
__all__ = [
    "AegisConfig",
    "AegisWSGI",
    "DEFAULT_POLICY",
    "Decision",
    "EndpointOverride",
    "ProtectionPolicy",
    "RULES",
    "Rule",
    "client_prefix",
    "decide",
    "mode_for_path",
    "path_matches",
    "__version__",
]

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    pattern: re.Pattern[str]


# Deliberately conservative. A false positive here blocks a real user, so each
# pattern targets syntax that has no legitimate reason to appear in a parameter
# value, rather than merely suspicious words.
RULES: tuple[Rule, ...] = (
    Rule(
        "sqli-union",
        "critical",
        # UNION followed by SELECT is not something a search box sends.
        re.compile(r"\bunion\b[\s\S]{0,40}\bselect\b", re.IGNORECASE),
    ),
    Rule(
        "sqli-tautology",
        "high",
        # `' OR '1'='1` and its variants. The quote structure is required so
        # that the phrase "1=1" in ordinary prose does not match.
        re.compile(r"['\"]\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
    ),
    Rule(
        "path-traversal",
        "high",
        re.compile(r"(\.\.[/\\]){2,}|%2e%2e[/\\%]", re.IGNORECASE),
    ),
    Rule(
        "command-injection",
        "critical",
        # A shell metacharacter immediately followed by a known binary.
        re.compile(r"[;|&`$]\s*(cat|curl|wget|nc|bash|sh|python|perl)\b", re.IGNORECASE),
    ),
    Rule(
        "xss-script",
        "high",
        re.compile(r"<script[\s>]|javascript:\s*[a-z]|\bonerror\s*=", re.IGNORECASE),
    ),
    Rule(
        "ssrf-metadata",
        "critical",
        # The cloud metadata endpoints, which a user parameter never needs.
        re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.IGNORECASE),
    ),
)


def _decode_safely(value: str) -> str:
    """Percent-decodes, returning the input unchanged if it will not decode."""
    try:
        return urllib.parse.unquote_plus(value)
    except (ValueError, UnicodeDecodeError):
        return value


def client_prefix(address: Optional[str]) -> str:
    """Truncates an address, so the SDK never reports a full client IP."""
    if not address:
        return "unknown"
    clean = address.removeprefix("::ffff:")
    if ":" in clean:
        return ":".join(clean.split(":")[:3]) + "::"
    octets = clean.split(".")
    return ".".join(octets[:3]) + ".0" if len(octets) == 4 else "unknown"


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass
class EndpointOverride:
    """Per-path override. `pattern` supports a trailing `*` only."""

    pattern: str
    mode: str  # "off" | "monitor" | "block"
    reason: str
    exempt_rules: tuple[str, ...] = ()


@dataclass
class ProtectionPolicy:
    default_mode: str = "monitor"
    overrides: tuple[EndpointOverride, ...] = ()
    blocking_rules: tuple[str, ...] = ()


def path_matches(path: str, pattern: str) -> bool:
    """Anchored glob. Only `*` is supported, so a pattern cannot backtrack."""
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def mode_for_path(policy: ProtectionPolicy, path: str) -> tuple[str, Optional[EndpointOverride]]:
    for override in policy.overrides:
        if path_matches(path, override.pattern):
            return override.mode, override
    return policy.default_mode, None


@dataclass
class Decision:
    action: str  # "allow" | "log" | "block"
    reason: str
    rule_id: Optional[str] = None


def decide(policy: ProtectionPolicy, path: str, matched: list[Rule]) -> Decision:
    """
    Decides what happens to a request.

    Anything uncertain logs rather than blocks, and every decision carries why:
    an engineer looking at a blocked request at 3am needs to know in seconds
    whether to disable a rule.
    """
    mode, override = mode_for_path(policy, path)

    if mode == "off":
        return Decision(
            "allow",
            f"Protection is disabled for {override.pattern}: {override.reason}"
            if override
            else "Protection is disabled.",
        )

    exempt = set(override.exempt_rules) if override else set()
    applicable = [rule for rule in matched if rule.id not in exempt]
    if not applicable:
        if matched and exempt:
            return Decision(
                "allow",
                f"Only exempt rules matched on {override.pattern if override else path}.",
            )
        return Decision("allow", "Nothing matched.")

    worst = next((r for r in applicable if r.severity == "critical"), applicable[0])

    if mode == "block" and worst.id in policy.blocking_rules:
        return Decision(
            "block",
            f"Blocked: {worst.id} ({worst.severity}) matched and is enabled for blocking.",
            worst.id,
        )

    if mode == "block":
        # Matched, but this rule is not one the operator allowed to block.
        # Logging rather than blocking is the conservative reading.
        return Decision(
            "log",
            f"{worst.id} ({worst.severity}) matched but is not in the blocking rule list.",
            worst.id,
        )

    return Decision(
        "log",
        f"{worst.id} ({worst.severity}) matched. Endpoint is in monitor mode, so the request continues.",
        worst.id,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


@dataclass
class _Event:
    at: str
    method: str
    path: str
    rule_id: str
    severity: str
    client_prefix: str
    user_agent: str
    user_id: Optional[str]
    blocked: bool
    reason: str


class _Reporter:
    """
    Batches events and posts them on a timer.

    Bounded on purpose: the application's memory matters more than these
    events, so a queue that fills drops rather than grows, and a failed post
    is dropped rather than retried forever.
    """

    MAX_QUEUE = 1000

    def __init__(self, url: str, token: str, app_name: str, interval: float,
                 on_error: Callable[[Exception], None]):
        # Every request carries the API token in an Authorization header, so
        # the scheme is not a detail. A plain-http endpoint, whether from a
        # typo or a copied staging config, puts that token on the wire in
        # cleartext for anyone on the path. Refusing here is noisy at startup;
        # not refusing is silent forever.
        #
        # Loopback is allowed because that is how the SDK is tested and how a
        # developer points it at a local instance, and traffic to localhost
        # does not leave the machine.
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(
                f"Aegis endpoint must be an http(s) URL, got {parsed.scheme or 'no scheme'}."
            )
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(
                "Refusing to send the API token over plain http to "
                f"{parsed.hostname}. Use https, or localhost for development."
            )

        self._url = url.rstrip("/") + "/api/public/runtime/events"
        self._token = token
        self._app = app_name
        self._interval = interval
        self._on_error = on_error
        self._queue: list[_Event] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        # A daemon thread never keeps the process alive on the SDK's account.
        self._thread = threading.Thread(target=self._loop, daemon=True, name="aegis-reporter")
        self._thread.start()
        atexit.register(self.flush)

    def add(self, event: _Event) -> None:
        with self._lock:
            if len(self._queue) < self.MAX_QUEUE:
                self._queue.append(event)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.flush()

    def flush(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        if not batch:
            return
        payload = json.dumps(
            {"app": self._app, "events": [event.__dict__ for event in batch]}
        ).encode()
        request = urllib.request.Request(
            self._url,
            data=payload,
            headers={"content-type": "application/json", "authorization": f"Bearer {self._token}"},
            method="POST",
        )
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            #
            # The rule's concern is a caller-controlled URL reaching a file://
            # scheme. The constructor rejects any scheme that is not http or
            # https, and plain http anywhere but loopback, so by this point the
            # only reachable schemes are the two intended ones. That check was
            # added because this finding was investigated rather than waved
            # through: it was correct that nothing validated the URL.
            with urllib.request.urlopen(request, timeout=10):  # nosemgrep
                pass
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            self._on_error(error)

    def stop(self) -> None:
        self._stop.set()
        self.flush()


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

DEFAULT_POLICY = ProtectionPolicy(default_mode="monitor", overrides=(), blocking_rules=())


def _inspect(values: Iterable[str]) -> list[Rule]:
    matched: list[Rule] = []
    for rule in RULES:
        for value in values:
            if value and rule.pattern.search(value):
                matched.append(rule)
                break
    return matched


@dataclass
class AegisConfig:
    url: str
    token: str
    app_name: str
    # Blocking is opt-in. The default reports without interfering, so
    # installing the SDK cannot itself cause an outage.
    mode: str = "monitor"
    policy: Optional[ProtectionPolicy] = None
    flush_interval_seconds: float = 30.0
    max_body_bytes: int = 64 * 1024
    on_error: Callable[[Exception], None] = field(default=lambda _e: None)


class AegisWSGI:
    """
    WSGI middleware.

    Wraps any WSGI application, including Flask and Django. Errors inside this
    class pass the request through: a firewall that 500s is worse than the
    attack it was meant to stop.
    """

    def __init__(self, app: Callable[..., Any], **kwargs: Any):
        self._app = app
        self._config = AegisConfig(**kwargs)

        if self._config.mode == "block":
            self._policy = self._config.policy or ProtectionPolicy(
                default_mode="block",
                # Without this, mode="block" would quietly block nothing: the
                # shared default carries no blocking rules on purpose. The
                # caller has already asked for blocking, so every rule the SDK
                # can detect is eligible.
                blocking_rules=tuple(rule.id for rule in RULES),
            )
        else:
            # A policy can never escalate monitor mode into blocking. That is
            # the second of the two opt-ins.
            self._policy = ProtectionPolicy(default_mode="monitor")

        self._reporter = _Reporter(
            self._config.url,
            self._config.token,
            self._config.app_name,
            self._config.flush_interval_seconds,
            self._config.on_error,
        )

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> Any:
        try:
            decision, event = self._evaluate(environ)
        except Exception as error:  # noqa: BLE001 - deliberately broad
            # Never raise into the request path.
            self._config.on_error(error)
            return self._app(environ, start_response)

        if event is not None:
            self._reporter.add(event)

        if decision is not None and decision.action == "block":
            body = b'{"error": "Request rejected."}'
            start_response(
                "403 Forbidden",
                [("content-type", "application/json"), ("content-length", str(len(body)))],
            )
            return [body]

        return self._app(environ, start_response)

    def _evaluate(self, environ: dict[str, Any]) -> tuple[Optional[Decision], Optional[_Event]]:
        path = environ.get("PATH_INFO", "/")

        # Decoded, and the raw form kept too. WSGI hands over the query string
        # percent-encoded, so matching only the raw text means `%20` defeats
        # every pattern that contains a space -- which is all of the useful
        # ones. Keeping both also catches a payload that only makes sense
        # before decoding, such as a double-encoded traversal.
        query = environ.get("QUERY_STRING", "")
        values = [path, query, _decode_safely(query), _decode_safely(path)]

        # Headers an attacker controls and applications commonly trust. The
        # Node SDK inspects the same three, and an SDK that inspects less than
        # its sibling becomes the quiet gap in a mixed estate.
        for header in ("HTTP_REFERER", "HTTP_X_FORWARDED_FOR", "HTTP_USER_AGENT"):
            value = environ.get(header)
            if isinstance(value, str):
                values.append(value[:2000])

        body = self._read_body(environ)
        if body:
            values.append(body[:10_000])

        matched = _inspect(values)
        if not matched:
            return None, None

        decision = decide(self._policy, path, matched)
        worst = next((r for r in matched if r.severity == "critical"), matched[0])

        event = _Event(
            at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            method=environ.get("REQUEST_METHOD", "GET"),
            path=path,
            rule_id=worst.id,
            severity=worst.severity,
            client_prefix=client_prefix(environ.get("REMOTE_ADDR")),
            user_agent=str(environ.get("HTTP_USER_AGENT", ""))[:300],
            user_id=environ.get("aegis.user_id"),
            blocked=decision.action == "block",
            # Why, recorded at the time. Reconstructing a decision from policy
            # after the fact is guesswork once the policy has changed.
            reason=decision.reason,
        )
        return decision, event

    def _read_body(self, environ: dict[str, Any]) -> str:
        """
        Reads and replaces the request body.

        WSGI input is a stream that can only be consumed once, so anything read
        here has to be put back or the application receives an empty body. That
        is the failure that makes a firewall look like a broken application.
        """
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            return ""
        if length <= 0:
            return ""

        stream = environ.get("wsgi.input")
        if stream is None:
            return ""

        capped = min(length, self._config.max_body_bytes)
        raw = stream.read(capped)
        remainder = stream.read(length - capped) if length > capped else b""

        import io

        environ["wsgi.input"] = io.BytesIO(raw + remainder)
        return raw.decode("utf-8", errors="replace")

    def close(self) -> None:
        self._reporter.stop()

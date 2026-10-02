"""
The Python SDK, exercised through a real WSGI server over real HTTP.

Not by calling the middleware directly: the failure modes that matter are a
consumed request body, a 500 raised from inside the firewall, and a thread that
outlives the process, and none of those are visible from a unit call.
"""

import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from wsgiref.simple_server import make_server

import pytest

from aegis_sarl import (
    RULES,
    AegisWSGI,
    _Reporter,
    EndpointOverride,
    ProtectionPolicy,
    client_prefix,
    decide,
    path_matches,
)

ATTACK = "1' UNION SELECT password FROM users"


def demo_app(environ, start_response):
    """An application that echoes its body, so a consumed body is visible."""
    length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(length) if length else b""
    payload = json.dumps({"ok": True, "received": body.decode("utf-8", "replace")}).encode()
    start_response("200 OK", [("content-type", "application/json")])
    return [payload]


class _Collector(BaseHTTPRequestHandler):
    """Stands in for the control plane and records what the SDK actually sends."""

    events = []

    def do_POST(self):  # noqa: N802 - required by BaseHTTPRequestHandler
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length)
        try:
            _Collector.events.extend(json.loads(body)["events"])
        except (ValueError, KeyError):
            pass
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):
        pass


@pytest.fixture
def stack():
    _Collector.events = []
    collector = HTTPServer(("127.0.0.1", 0), _Collector)
    threading.Thread(target=collector.serve_forever, daemon=True).start()

    def build(mode="monitor", policy=None):
        middleware = AegisWSGI(
            demo_app,
            url=f"http://127.0.0.1:{collector.server_port}",
            token="test-token",
            app_name="pytest",
            mode=mode,
            policy=policy,
            flush_interval_seconds=0.5,
        )
        server = make_server("127.0.0.1", 0, middleware)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return middleware, f"http://127.0.0.1:{server.server_port}", server

    created = []

    def factory(**kwargs):
        middleware, base, server = build(**kwargs)
        created.append((middleware, server))
        return base

    yield factory

    for middleware, server in created:
        middleware.close()
        server.shutdown()
    collector.shutdown()


def get(url):
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        # The URL is this test's own local fixture server.
        with urllib.request.urlopen(url, timeout=5) as response:  # nosemgrep
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def post(url, body):
    request = urllib.request.Request(
        url, data=body.encode(), headers={"content-type": "application/json"}, method="POST"
    )
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        # The URL is this test's own local fixture server.
        with urllib.request.urlopen(request, timeout=5) as response:  # nosemgrep
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


class TestMonitorMode:
    def test_a_clean_request_passes(self, stack):
        base = stack()
        status, body = get(f"{base}/search?q=hello")
        assert status == 200
        assert json.loads(body)["ok"] is True

    def test_an_attack_is_reported_but_not_blocked(self, stack):
        base = stack()
        status, _ = get(f"{base}/api?q={urllib.parse.quote(ATTACK)}")
        # Monitor mode is the default precisely so that installing the SDK
        # cannot itself cause an outage.
        assert status == 200

        time.sleep(1.2)
        assert len(_Collector.events) > 0
        event = _Collector.events[0]
        assert event["rule_id"] == "sqli-union"
        assert event["blocked"] is False
        assert "monitor" in event["reason"].lower()

    def test_the_client_ip_is_truncated(self, stack):
        base = stack()
        get(f"{base}/api?q={urllib.parse.quote(ATTACK)}")
        time.sleep(1.2)
        assert _Collector.events
        # A full client IP is personal data the control plane has no use for.
        assert _Collector.events[0]["client_prefix"].endswith(".0")


class TestBlockMode:
    def test_block_mode_with_no_policy_actually_blocks(self, stack):
        # The regression this guards: a shared default policy carries no
        # blocking rules on purpose, so mode="block" would quietly block
        # nothing at all.
        base = stack(mode="block")
        status, _ = get(f"{base}/api?q={urllib.parse.quote(ATTACK)}")
        assert status == 403

    def test_an_exempt_endpoint_passes_the_same_attack(self, stack):
        policy = ProtectionPolicy(
            default_mode="block",
            overrides=(
                EndpointOverride(
                    pattern="/webhooks/*",
                    mode="monitor",
                    reason="Third-party payloads look like attacks and we do not control them.",
                ),
            ),
            blocking_rules=("sqli-union", "command-injection"),
        )
        base = stack(mode="block", policy=policy)

        blocked, _ = get(f"{base}/api?q={urllib.parse.quote(ATTACK)}")
        exempt, _ = get(f"{base}/webhooks/stripe?q={urllib.parse.quote(ATTACK)}")

        assert blocked == 403
        # Same payload, different outcome: that is the point of per-endpoint
        # policy, and without it the only way to stop blocking one misfiring
        # endpoint is to stop blocking everywhere.
        assert exempt == 200

        time.sleep(1.2)
        paths = {event["path"]: event for event in _Collector.events}
        assert paths["/api"]["blocked"] is True
        assert paths["/webhooks/stripe"]["blocked"] is False
        # The exempt endpoint is still reported, so the attack stays visible.
        assert paths["/webhooks/stripe"]["rule_id"] == "sqli-union"

    def test_monitor_mode_cannot_be_escalated_by_a_policy(self, stack):
        # Blocking takes two separate opt-ins, and this is the second missing.
        policy = ProtectionPolicy(
            default_mode="block", blocking_rules=tuple(rule.id for rule in RULES)
        )
        base = stack(mode="monitor", policy=policy)
        status, _ = get(f"{base}/api?q={urllib.parse.quote(ATTACK)}")
        assert status == 200


class TestRequestBody:
    def test_the_application_still_receives_its_body(self, stack):
        # WSGI input can only be read once. Reading it for inspection without
        # putting it back makes every POST arrive empty, which looks like a
        # broken application rather than a broken firewall.
        base = stack()
        status, body = post(f"{base}/submit", '{"name": "hello world"}')
        assert status == 200
        assert json.loads(body)["received"] == '{"name": "hello world"}'

    def test_an_attack_in_the_body_is_detected(self, stack):
        base = stack(mode="block")
        status, _ = post(f"{base}/api", json.dumps({"q": ATTACK}))
        assert status == 403

    def test_a_body_larger_than_the_cap_still_reaches_the_application(self, stack):
        base = stack()
        payload = json.dumps({"data": "x" * 200_000})
        status, body = post(f"{base}/submit", payload)
        assert status == 200
        # The inspection is capped, but the application must still get all of
        # it. Truncating a real request would corrupt data.
        assert json.loads(body)["received"] == payload


class TestFailureBehaviour:
    def test_a_broken_application_is_not_masked(self, stack):
        # The firewall must not convert an application error into something
        # else, or debugging becomes impossible.
        def broken(environ, start_response):
            raise RuntimeError("application failure")

        middleware = AegisWSGI(
            broken, url="http://127.0.0.1:1", token="t", app_name="x", flush_interval_seconds=60
        )
        with pytest.raises(RuntimeError):
            middleware({"PATH_INFO": "/", "REQUEST_METHOD": "GET"}, lambda *_: None)
        middleware.close()

    def test_an_unreachable_control_plane_does_not_break_requests(self, stack):
        errors = []
        middleware = AegisWSGI(
            demo_app,
            url="http://127.0.0.1:1",
            token="t",
            app_name="x",
            flush_interval_seconds=0.3,
            on_error=errors.append,
        )
        server = make_server("127.0.0.1", 0, middleware)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            status, _ = get(f"http://127.0.0.1:{server.server_port}/api?q={urllib.parse.quote(ATTACK)}")
            # Reporting is best-effort; the request is not.
            assert status == 200
            time.sleep(1.0)
            assert errors, "a failed report should surface through on_error"
        finally:
            middleware.close()
            server.shutdown()


class TestPureDecisions:
    def test_path_matching_is_anchored(self):
        assert path_matches("/webhooks/stripe", "/webhooks/*")
        assert path_matches("/api", "/api")
        # A prefix that is not a glob must not match by accident.
        assert not path_matches("/api/v2", "/api")
        # And a pattern must not match something merely containing it.
        assert not path_matches("/public/webhooks", "/webhooks/*")

    def test_an_exempt_rule_does_not_block(self):
        policy = ProtectionPolicy(
            default_mode="block",
            overrides=(
                EndpointOverride(
                    pattern="/import",
                    mode="block",
                    reason="Bulk import.",
                    exempt_rules=("sqli-union",),
                ),
            ),
            blocking_rules=("sqli-union",),
        )
        matched = [rule for rule in RULES if rule.id == "sqli-union"]
        assert decide(policy, "/import", matched).action == "allow"

    def test_a_rule_not_in_the_blocking_list_logs_instead(self):
        policy = ProtectionPolicy(default_mode="block", blocking_rules=("command-injection",))
        matched = [rule for rule in RULES if rule.id == "sqli-union"]
        decision = decide(policy, "/api", matched)
        # Matched but not authorised to block: the conservative reading.
        assert decision.action == "log"
        assert "not in the blocking rule list" in decision.reason

    def test_addresses_are_truncated_not_hashed(self):
        assert client_prefix("192.0.2.44") == "192.0.2.0"
        assert client_prefix("::ffff:192.0.2.44") == "192.0.2.0"
        assert client_prefix(None) == "unknown"
        assert client_prefix("2001:db8:85a3::8a2e") == "2001:db8:85a3::"


def test_refuses_plain_http_endpoint():
    """The token travels in an Authorization header on every request.

    A plain-http endpoint puts it on the wire in cleartext, and the usual
    cause is a copied staging config rather than anything deliberate, so the
    failure has to be loud at startup instead of silent forever.
    """
    try:
        _Reporter(url="http://scanner.example.com", token="t", app_name="a",
                interval=1.0, on_error=lambda e: None)
    except ValueError as error:
        assert "plain http" in str(error)
    else:
        raise AssertionError("plain-http endpoint was accepted")


def test_allows_localhost_over_http():
    """Development and the test suite both point at a local instance.

    Traffic to loopback does not leave the machine, so refusing it would
    only teach people to disable the check.
    """
    sender = _Reporter(url="http://localhost:8080", token="t", app_name="a",
                     interval=1.0, on_error=lambda e: None)
    assert sender._url.endswith("/api/public/runtime/events")


def test_refuses_non_http_scheme():
    """A file:// or gopher:// URL is a misconfiguration, not a transport."""
    try:
        _Reporter(url="file:///etc/passwd", token="t", app_name="a",
                interval=1.0, on_error=lambda e: None)
    except ValueError as error:
        assert "http(s)" in str(error)
    else:
        raise AssertionError("non-http scheme was accepted")

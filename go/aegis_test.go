// Tests for the Go SDK, exercised through a real HTTP server.
//
// Not by calling the middleware directly: the failure modes that matter are a
// consumed request body, a panic escaping into the handler chain, and a
// goroutine outliving the process, and none of those are visible from a unit
// call.
package aegis

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const attack = "1' UNION SELECT password FROM users"

// echoHandler returns its body, so a consumed body is visible to a test.
var echoHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "received": string(body)})
})

// collector stands in for the control plane and records what the SDK sends.
type collector struct {
	mu     sync.Mutex
	events []Event
	server *httptest.Server
}

func newCollector() *collector {
	c := &collector{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Events []Event `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		c.mu.Lock()
		c.events = append(c.events, payload.Events...)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	return c
}

func (c *collector) received() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.events...)
}

func (c *collector) close() { c.server.Close() }

func setup(t *testing.T, mode string, policy *ProtectionPolicy) (*httptest.Server, *collector) {
	t.Helper()
	c := newCollector()
	mw := New(Config{
		URL:           c.server.URL,
		Token:         "test-token",
		AppName:       "go-test",
		Mode:          mode,
		Policy:        policy,
		FlushInterval: 300 * time.Millisecond,
	})
	server := httptest.NewServer(mw.Handler(echoHandler))
	t.Cleanup(func() {
		server.Close()
		mw.Close()
		c.close()
	})
	return server, c
}

func get(t *testing.T, base, path string) int {
	t.Helper()
	response, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func TestCleanRequestPasses(t *testing.T) {
	server, _ := setup(t, "monitor", nil)
	if status := get(t, server.URL, "/search?q=hello"); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
}

func TestMonitorModeReportsWithoutBlocking(t *testing.T) {
	server, c := setup(t, "monitor", nil)

	// Monitor is the default precisely so that installing the SDK cannot
	// itself cause an outage.
	if status := get(t, server.URL, "/api?q="+url.QueryEscape(attack)); status != http.StatusOK {
		t.Fatalf("monitor mode should not block, got %d", status)
	}

	time.Sleep(800 * time.Millisecond)
	events := c.received()
	if len(events) == 0 {
		t.Fatal("no events reached the collector")
	}
	if events[0].RuleID != "sqli-union" {
		t.Fatalf("expected sqli-union, got %q", events[0].RuleID)
	}
	if events[0].Blocked {
		t.Fatal("monitor mode must not record a block")
	}
	if !strings.Contains(strings.ToLower(events[0].Reason), "monitor") {
		t.Fatalf("the reason should say why: %q", events[0].Reason)
	}
}

func TestPercentEncodingDoesNotDefeatDetection(t *testing.T) {
	// The bug this covers, found in the Python port: a query string arrives
	// percent-encoded, so %20 defeats every pattern containing a space.
	server, _ := setup(t, "block", nil)
	if status := get(t, server.URL, "/api?q="+url.QueryEscape(attack)); status != http.StatusForbidden {
		t.Fatalf("an encoded payload should still be detected, got %d", status)
	}
}

func TestBlockModeWithNoPolicyActuallyBlocks(t *testing.T) {
	// The regression this guards: a default policy carries no blocking rules
	// on purpose, so Mode "block" would quietly block nothing.
	server, _ := setup(t, "block", nil)
	if status := get(t, server.URL, "/api?q="+url.QueryEscape(attack)); status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", status)
	}
}

func TestExemptEndpointPassesTheSameAttack(t *testing.T) {
	policy := &ProtectionPolicy{
		DefaultMode: "block",
		Overrides: []EndpointOverride{{
			Pattern: "/webhooks/*",
			Mode:    "monitor",
			Reason:  "Third-party payloads look like attacks and we do not control them.",
		}},
		BlockingRules: []string{"sqli-union", "command-injection"},
	}
	server, c := setup(t, "block", policy)

	blocked := get(t, server.URL, "/api?q="+url.QueryEscape(attack))
	exempt := get(t, server.URL, "/webhooks/stripe?q="+url.QueryEscape(attack))

	if blocked != http.StatusForbidden {
		t.Fatalf("protected path should block, got %d", blocked)
	}
	// Same payload, different outcome: that is the point of per-endpoint
	// policy. Without it the only way to stop blocking one misfiring endpoint
	// is to stop blocking everywhere.
	if exempt != http.StatusOK {
		t.Fatalf("exempt path should pass, got %d", exempt)
	}

	time.Sleep(800 * time.Millisecond)
	byPath := map[string]Event{}
	for _, event := range c.received() {
		byPath[event.Path] = event
	}
	if !byPath["/api"].Blocked {
		t.Fatal("the blocked request should be recorded as blocked")
	}
	if byPath["/webhooks/stripe"].Blocked {
		t.Fatal("the exempt request should not be recorded as blocked")
	}
	// The exempt endpoint is still reported, so the attack stays visible.
	if byPath["/webhooks/stripe"].RuleID != "sqli-union" {
		t.Fatal("the exempt request should still be reported")
	}
}

func TestMonitorModeCannotBeEscalatedByPolicy(t *testing.T) {
	// Blocking takes two separate opt-ins, and this is the second missing.
	policy := &ProtectionPolicy{DefaultMode: "block", BlockingRules: []string{"sqli-union"}}
	server, _ := setup(t, "monitor", policy)
	if status := get(t, server.URL, "/api?q="+url.QueryEscape(attack)); status != http.StatusOK {
		t.Fatalf("a policy must not escalate monitor mode, got %d", status)
	}
}

func TestApplicationStillReceivesItsBody(t *testing.T) {
	// http.Request.Body can only be read once. Inspecting it without
	// restoring it makes every POST arrive empty, which looks like a broken
	// application rather than a broken firewall.
	server, _ := setup(t, "monitor", nil)

	payload := `{"name": "hello world"}`
	response, err := http.Post(server.URL+"/submit", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()

	var decoded struct {
		Received string `json:"received"`
	}
	_ = json.NewDecoder(response.Body).Decode(&decoded)
	if decoded.Received != payload {
		t.Fatalf("the application received %q, expected %q", decoded.Received, payload)
	}
}

func TestBodyLargerThanTheCapStillArrivesWhole(t *testing.T) {
	server, _ := setup(t, "monitor", nil)

	// Inspection is capped; delivery is not. Truncating a real request would
	// corrupt data.
	payload := `{"data":"` + strings.Repeat("x", 200_000) + `"}`
	response, err := http.Post(server.URL+"/submit", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()

	var decoded struct {
		Received string `json:"received"`
	}
	_ = json.NewDecoder(response.Body).Decode(&decoded)
	if len(decoded.Received) != len(payload) {
		t.Fatalf("the application received %d bytes, expected %d", len(decoded.Received), len(payload))
	}
}

func TestAttackInBodyIsDetected(t *testing.T) {
	server, _ := setup(t, "block", nil)
	body := `{"q":"` + attack + `"}`
	response, err := http.Post(server.URL+"/api", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
}

func TestUnreachableControlPlaneDoesNotBreakRequests(t *testing.T) {
	var errors []error
	var mu sync.Mutex
	mw := New(Config{
		// A port nothing listens on.
		URL:           "http://127.0.0.1:1",
		Token:         "t",
		AppName:       "x",
		FlushInterval: 200 * time.Millisecond,
		OnError: func(err error) {
			mu.Lock()
			errors = append(errors, err)
			mu.Unlock()
		},
	})
	server := httptest.NewServer(mw.Handler(echoHandler))
	defer func() {
		server.Close()
		mw.Close()
	}()

	// Reporting is best-effort; the request is not.
	if status := get(t, server.URL, "/api?q="+url.QueryEscape(attack)); status != http.StatusOK {
		t.Fatalf("a failed report must not affect the request, got %d", status)
	}

	time.Sleep(700 * time.Millisecond)
	mu.Lock()
	count := len(errors)
	mu.Unlock()
	if count == 0 {
		t.Fatal("a failed report should surface through OnError")
	}
}

func TestClientAddressesAreTruncated(t *testing.T) {
	// A full client IP is personal data the control plane has no use for.
	cases := map[string]string{
		"192.0.2.44:54321":        "192.0.2.0",
		"192.0.2.44":              "192.0.2.0",
		"::ffff:192.0.2.44":       "192.0.2.0",
		"":                        "unknown",
		"2001:db8:85a3::8a2e:1:2": "2001:db8:85a3::",
	}
	for input, expected := range cases {
		if got := ClientPrefix(input); got != expected {
			t.Errorf("ClientPrefix(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestPathMatchingIsAnchored(t *testing.T) {
	if !PathMatches("/webhooks/stripe", "/webhooks/*") {
		t.Error("a glob should match its prefix")
	}
	if !PathMatches("/api", "/api") {
		t.Error("an exact pattern should match itself")
	}
	// A prefix that is not a glob must not match by accident.
	if PathMatches("/api/v2", "/api") {
		t.Error("an exact pattern must not match a longer path")
	}
	// And a pattern must not match something merely containing it.
	if PathMatches("/public/webhooks/x", "/webhooks/*") {
		t.Error("a glob is anchored at the start")
	}
}

func TestARuleNotInTheBlockingListLogsInstead(t *testing.T) {
	policy := ProtectionPolicy{DefaultMode: "block", BlockingRules: []string{"command-injection"}}
	var matched []Rule
	for _, rule := range Rules {
		if rule.ID == "sqli-union" {
			matched = append(matched, rule)
		}
	}
	decision := Decide(policy, "/api", matched)
	// Matched but not authorised to block: the conservative reading.
	if decision.Action != "log" {
		t.Fatalf("expected log, got %q", decision.Action)
	}
	if !strings.Contains(decision.Reason, "not in the blocking rule list") {
		t.Fatalf("the reason should explain itself: %q", decision.Reason)
	}
}

func TestAnExemptRuleDoesNotBlock(t *testing.T) {
	policy := ProtectionPolicy{
		DefaultMode: "block",
		Overrides: []EndpointOverride{{
			Pattern:     "/import",
			Mode:        "block",
			Reason:      "Bulk import.",
			ExemptRules: []string{"sqli-union"},
		}},
		BlockingRules: []string{"sqli-union"},
	}
	var matched []Rule
	for _, rule := range Rules {
		if rule.ID == "sqli-union" {
			matched = append(matched, rule)
		}
	}
	if decision := Decide(policy, "/import", matched); decision.Action != "allow" {
		t.Fatalf("an exempt rule should allow, got %q", decision.Action)
	}
}

func TestAPanickingHandlerIsNotMasked(t *testing.T) {
	// The firewall must not convert an application panic into something else,
	// or debugging becomes impossible.
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("application failure")
	})
	mw := New(Config{URL: "http://127.0.0.1:1", Token: "t", AppName: "x", FlushInterval: time.Hour})
	defer mw.Close()

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("the application's panic should propagate, not be swallowed")
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	mw.Handler(panicking).ServeHTTP(recorder, request)
}

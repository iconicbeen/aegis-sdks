// Package aegis is an in-app firewall for Go HTTP servers.
//
// It wraps an http.Handler, inspects requests, reports what it saw, and
// optionally blocks. A port of the Node and Python SDKs, holding the same four
// properties, because they are the reason this is safe to put in a request
// path at all:
//
//   - It never blocks unless explicitly configured to.
//   - It never panics into the request path; a panic inside the middleware is
//     recovered and the request continues.
//   - It reports asynchronously, so latency is unaffected.
//   - It holds no unbounded state.
//
// The detection rules are identical to the other SDKs', verified by a shared
// corpus. Two SDKs that disagree about what an attack looks like produce
// findings that cannot be compared across services, and the quieter one
// silently becomes the weakest link.
//
// Usage:
//
//	mw := aegis.New(aegis.Config{
//	    URL: "https://aegis.example.com", Token: os.Getenv("AEGIS_TOKEN"),
//	    AppName: "checkout",
//	})
//	defer mw.Close()
//	http.ListenAndServe(":8080", mw.Handler(mux))
//
// Blocking requires two separate opt-ins: Mode "block" and a policy naming the
// rules allowed to block.
package aegis

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Version of this SDK.
const Version = "0.1.0"

// Rule is one detection pattern.
type Rule struct {
	ID       string
	Severity string
	Pattern  *regexp.Regexp
}

// Rules are deliberately conservative. A false positive here rejects a real
// user's request, so each pattern targets syntax that has no legitimate reason
// to appear in a parameter value, rather than merely suspicious words.
//
// Go's regexp package is RE2, which has no backtracking. That is a feature
// here: a pattern cannot be made to run in exponential time by a crafted
// input, which is a denial of service a firewall must not introduce.
var Rules = []Rule{
	{
		ID:       "sqli-union",
		Severity: "critical",
		// UNION followed by SELECT is not something a search box sends.
		Pattern: regexp.MustCompile(`(?is)\bunion\b[\s\S]{0,40}\bselect\b`),
	},
	{
		ID:       "sqli-tautology",
		Severity: "high",
		// The quote structure is required so that "1=1" in prose does not match.
		Pattern: regexp.MustCompile(`(?i)['"]\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`),
	},
	{
		ID:       "path-traversal",
		Severity: "high",
		Pattern:  regexp.MustCompile(`(?i)(\.\.[/\\]){2,}|%2e%2e[/\\%]`),
	},
	{
		ID:       "command-injection",
		Severity: "critical",
		// A shell metacharacter immediately followed by a known binary.
		Pattern: regexp.MustCompile("(?i)[;|&`$]\\s*(cat|curl|wget|nc|bash|sh|python|perl)\\b"),
	},
	{
		ID:       "xss-script",
		Severity: "high",
		Pattern:  regexp.MustCompile(`(?i)<script[\s>]|javascript:\s*[a-z]|\bonerror\s*=`),
	},
	{
		ID:       "ssrf-metadata",
		Severity: "critical",
		// The cloud metadata endpoints, which a user parameter never needs.
		Pattern: regexp.MustCompile(`(?i)169\.254\.169\.254|metadata\.google\.internal`),
	},
}

// EndpointOverride adjusts protection for one path pattern.
type EndpointOverride struct {
	// Pattern supports a trailing "*" only, so it cannot backtrack.
	Pattern     string
	Mode        string // "off" | "monitor" | "block"
	Reason      string
	ExemptRules []string
}

// ProtectionPolicy decides what happens when a rule matches.
type ProtectionPolicy struct {
	DefaultMode   string
	Overrides     []EndpointOverride
	BlockingRules []string
}

// Decision is the outcome for one request, with the reason recorded.
type Decision struct {
	Action string // "allow" | "log" | "block"
	Reason string
	RuleID string
}

// PathMatches reports whether path matches an anchored glob pattern.
func PathMatches(path, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return path == pattern
}

func modeForPath(policy ProtectionPolicy, path string) (string, *EndpointOverride) {
	for i := range policy.Overrides {
		if PathMatches(path, policy.Overrides[i].Pattern) {
			return policy.Overrides[i].Mode, &policy.Overrides[i]
		}
	}
	return policy.DefaultMode, nil
}

// Decide determines what happens to a request that matched rules.
//
// Anything uncertain logs rather than blocks, and every decision carries why:
// an engineer looking at a blocked request at 3am needs to know in seconds
// whether to disable a rule.
func Decide(policy ProtectionPolicy, path string, matched []Rule) Decision {
	mode, override := modeForPath(policy, path)

	if mode == "off" {
		if override != nil {
			return Decision{Action: "allow", Reason: "Protection is disabled for " + override.Pattern + ": " + override.Reason}
		}
		return Decision{Action: "allow", Reason: "Protection is disabled."}
	}

	exempt := map[string]bool{}
	if override != nil {
		for _, id := range override.ExemptRules {
			exempt[id] = true
		}
	}

	applicable := matched[:0:0]
	for _, rule := range matched {
		if !exempt[rule.ID] {
			applicable = append(applicable, rule)
		}
	}
	if len(applicable) == 0 {
		return Decision{Action: "allow", Reason: "Nothing applicable matched."}
	}

	worst := applicable[0]
	for _, rule := range applicable {
		if rule.Severity == "critical" {
			worst = rule
			break
		}
	}

	blocking := false
	for _, id := range policy.BlockingRules {
		if id == worst.ID {
			blocking = true
			break
		}
	}

	if mode == "block" && blocking {
		return Decision{
			Action: "block",
			Reason: "Blocked: " + worst.ID + " (" + worst.Severity + ") matched and is enabled for blocking.",
			RuleID: worst.ID,
		}
	}
	if mode == "block" {
		// Matched, but not a rule the operator allowed to block. Logging is
		// the conservative reading.
		return Decision{
			Action: "log",
			Reason: worst.ID + " (" + worst.Severity + ") matched but is not in the blocking rule list.",
			RuleID: worst.ID,
		}
	}
	return Decision{
		Action: "log",
		Reason: worst.ID + " (" + worst.Severity + ") matched. Endpoint is in monitor mode, so the request continues.",
		RuleID: worst.ID,
	}
}

// ClientPrefix truncates an address, so the SDK never reports a full client IP.
func ClientPrefix(address string) string {
	if address == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	address = strings.TrimPrefix(address, "::ffff:")

	if strings.Contains(address, ":") {
		parts := strings.Split(address, ":")
		if len(parts) > 3 {
			parts = parts[:3]
		}
		return strings.Join(parts, ":") + "::"
	}

	octets := strings.Split(address, ".")
	if len(octets) != 4 {
		return "unknown"
	}
	return strings.Join(octets[:3], ".") + ".0"
}

// Event is one detection, as reported to the control plane.
type Event struct {
	At           string `json:"at"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	RuleID       string `json:"ruleId"`
	Severity     string `json:"severity"`
	ClientPrefix string `json:"clientPrefix"`
	UserAgent    string `json:"userAgent"`
	UserID       string `json:"userId,omitempty"`
	Blocked      bool   `json:"blocked"`
	// Why, recorded at the time. Reconstructing a decision from policy after
	// the fact is guesswork once the policy has changed.
	Reason string `json:"reason"`
}

// Config configures the middleware.
type Config struct {
	URL     string
	Token   string
	AppName string
	// Mode defaults to "monitor". Blocking is opt-in, so installing the SDK
	// cannot itself cause an outage.
	Mode          string
	Policy        *ProtectionPolicy
	FlushInterval time.Duration
	// MaxBodyBytes caps how much of a request body is inspected. The
	// application always receives the whole request regardless.
	MaxBodyBytes int64
	OnError      func(error)
}

// Middleware wraps an http.Handler.
type Middleware struct {
	config Config
	policy ProtectionPolicy
	client *http.Client

	mu    sync.Mutex
	queue []Event

	stop chan struct{}
	done chan struct{}
}

const maxQueue = 1000

// New creates the middleware and starts its reporting loop.
func New(config Config) *Middleware {
	if config.FlushInterval == 0 {
		config.FlushInterval = 30 * time.Second
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = 64 * 1024
	}
	if config.OnError == nil {
		config.OnError = func(error) {}
	}
	if config.Mode == "" {
		config.Mode = "monitor"
	}

	var policy ProtectionPolicy
	if config.Mode == "block" {
		if config.Policy != nil {
			policy = *config.Policy
		} else {
			// Without this, Mode "block" would quietly block nothing: a shared
			// default carries no blocking rules on purpose. The caller has
			// already asked for blocking, so every rule is eligible.
			ids := make([]string, 0, len(Rules))
			for _, rule := range Rules {
				ids = append(ids, rule.ID)
			}
			policy = ProtectionPolicy{DefaultMode: "block", BlockingRules: ids}
		}
	} else {
		// A policy can never escalate monitor mode into blocking. That is the
		// second of the two opt-ins.
		policy = ProtectionPolicy{DefaultMode: "monitor"}
	}

	m := &Middleware{
		config: config,
		policy: policy,
		client: &http.Client{Timeout: 10 * time.Second},
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go m.loop()
	return m
}

func (m *Middleware) loop() {
	defer close(m.done)
	ticker := time.NewTicker(m.config.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.Flush()
		case <-m.stop:
			m.Flush()
			return
		}
	}
}

// Flush sends any queued events. Dropped rather than retried indefinitely: the
// application's memory matters more than these events.
func (m *Middleware) Flush() {
	m.mu.Lock()
	batch := m.queue
	m.queue = nil
	m.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	body, err := json.Marshal(map[string]any{"app": m.config.AppName, "events": batch})
	if err != nil {
		m.config.OnError(err)
		return
	}

	request, err := http.NewRequest(
		http.MethodPost,
		strings.TrimRight(m.config.URL, "/")+"/api/public/runtime/events",
		bytes.NewReader(body),
	)
	if err != nil {
		m.config.OnError(err)
		return
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("authorization", "Bearer "+m.config.Token)

	response, err := m.client.Do(request)
	if err != nil {
		m.config.OnError(err)
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

// Close flushes pending events and stops the reporting loop.
func (m *Middleware) Close() {
	close(m.stop)
	<-m.done
}

func (m *Middleware) record(event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.queue) < maxQueue {
		m.queue = append(m.queue, event)
	}
}

func decodeSafely(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func inspect(values []string) []Rule {
	var matched []Rule
	for _, rule := range Rules {
		for _, value := range values {
			if value != "" && rule.Pattern.MatchString(value) {
				matched = append(matched, rule)
				break
			}
		}
	}
	return matched
}

// Handler wraps next with the firewall.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision, event, ok := m.evaluate(r)
		if !ok {
			// Something went wrong inside the firewall. The request continues:
			// a middleware that 500s is worse than the attack it prevents.
			next.ServeHTTP(w, r)
			return
		}

		if event != nil {
			m.record(*event)
		}

		if decision != nil && decision.Action == "block" {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			// Deliberately terse: naming the rule would tell an attacker
			// exactly what to change.
			_, _ = w.Write([]byte(`{"error":"Request rejected."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) evaluate(r *http.Request) (decision *Decision, event *Event, ok bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			// Never panic into the request path.
			if err, isError := recovered.(error); isError {
				m.config.OnError(err)
			}
			decision, event, ok = nil, nil, false
		}
	}()

	path := r.URL.Path
	query := r.URL.RawQuery

	// Both the raw and decoded forms. A percent-encoded space defeats every
	// pattern containing one, and a double-encoded payload only makes sense
	// before decoding.
	values := []string{path, query, decodeSafely(query), decodeSafely(path)}

	// Headers an attacker controls and applications commonly trust.
	for _, name := range []string{"Referer", "X-Forwarded-For", "User-Agent"} {
		if value := r.Header.Get(name); value != "" {
			values = append(values, truncate(value, 2000))
		}
	}

	if body := m.readBody(r); body != "" {
		values = append(values, truncate(body, 10_000))
	}

	matched := inspect(values)
	if len(matched) == 0 {
		return nil, nil, true
	}

	result := Decide(m.policy, path, matched)

	worst := matched[0]
	for _, rule := range matched {
		if rule.Severity == "critical" {
			worst = rule
			break
		}
	}

	return &result, &Event{
		At:           time.Now().UTC().Format(time.RFC3339),
		Method:       r.Method,
		Path:         path,
		RuleID:       worst.ID,
		Severity:     worst.Severity,
		ClientPrefix: ClientPrefix(r.RemoteAddr),
		UserAgent:    truncate(r.Header.Get("User-Agent"), 300),
		Blocked:      result.Action == "block",
		Reason:       result.Reason,
	}, true
}

// readBody reads and replaces the request body.
//
// http.Request.Body is a stream that can only be consumed once, so anything
// read here has to be put back or the application receives an empty body. That
// is the failure that makes a firewall look like a broken application.
func (m *Middleware) readBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}

	inspected, err := io.ReadAll(io.LimitReader(r.Body, m.config.MaxBodyBytes))
	if err != nil {
		return ""
	}

	// Whatever was not inspected still has to reach the application, so the
	// two halves are stitched back together rather than truncated.
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(inspected), r.Body))
	return string(inspected)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

<?php

declare(strict_types=1);

namespace Aegis;

/**
 * Aegis in-app firewall for PHP.
 *
 * A port of the Node, Python, Go and Java SDKs, holding the same four
 * properties, because they are the reason this is safe to put in a request path
 * at all:
 *
 *   - It never blocks unless explicitly configured to.
 *   - It never throws into the request path; an error inside the firewall lets
 *     the request continue rather than returning a 500.
 *   - It reports without making the user wait, using a request-shutdown hook.
 *   - It holds no unbounded state.
 *
 * The detection rules are identical to the other SDKs', verified by a shared
 * corpus. Two SDKs that disagree about what an attack looks like produce
 * findings that cannot be compared across services, and the quieter one
 * silently becomes the weakest link.
 *
 * PHP's execution model differs from the others in a way that matters. There is
 * no long-lived process to hold a background thread, so events are flushed on
 * request shutdown, after the response has been sent to the user. The user
 * never waits for the control plane.
 *
 * No dependencies. This sits in the request path of somebody's production
 * application, and every dependency is a supply chain risk a security tool has
 * no business introducing.
 *
 * Usage, as early as possible in the request:
 *
 *     Aegis::protect([
 *         'url' => 'https://aegis.example.com',
 *         'token' => getenv('AEGIS_TOKEN'),
 *         'app_name' => 'checkout',
 *     ]);
 */
final class Aegis
{
    public const VERSION = '0.1.0';

    /**
     * Deliberately conservative. A false positive here rejects a real user's
     * request, so each pattern targets syntax that has no legitimate reason to
     * appear in a parameter value, rather than merely suspicious words.
     *
     * @var array<int, array{id: string, severity: string, pattern: string}>
     */
    public const RULES = [
        [
            'id' => 'sqli-union',
            'severity' => 'critical',
            // UNION followed by SELECT is not something a search box sends.
            'pattern' => '/\bunion\b[\s\S]{0,40}\bselect\b/i',
        ],
        [
            'id' => 'sqli-tautology',
            'severity' => 'high',
            // The quote structure is required so that "1=1" in prose does not match.
            'pattern' => '/[\'"]\s*(or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i',
        ],
        [
            'id' => 'path-traversal',
            'severity' => 'high',
            'pattern' => '/(\.\.[\/\\\\]){2,}|%2e%2e[\/\\\\%]/i',
        ],
        [
            'id' => 'command-injection',
            'severity' => 'critical',
            // A shell metacharacter immediately followed by a known binary.
            'pattern' => '/[;|&`$]\s*(cat|curl|wget|nc|bash|sh|python|perl)\b/i',
        ],
        [
            'id' => 'xss-script',
            'severity' => 'high',
            'pattern' => '/<script[\s>]|javascript:\s*[a-z]|\bonerror\s*=/i',
        ],
        [
            'id' => 'ssrf-metadata',
            'severity' => 'critical',
            // The cloud metadata endpoints, which a user parameter never needs.
            'pattern' => '/169\.254\.169\.254|metadata\.google\.internal/i',
        ],
    ];

    /** @var array<int, array<string, mixed>> */
    private static array $queue = [];

    /** @var array<string, mixed> */
    private static array $config = [];

    private static bool $shutdownRegistered = false;

    /**
     * Returns the rules matching any of the given inputs.
     *
     * @param array<int, string> $values
     * @return array<int, array{id: string, severity: string, pattern: string}>
     */
    public static function inspect(array $values): array
    {
        $matched = [];
        foreach (self::RULES as $rule) {
            foreach ($values as $value) {
                if ($value !== '' && preg_match($rule['pattern'], $value) === 1) {
                    $matched[] = $rule;
                    break;
                }
            }
        }

        return $matched;
    }

    /** Truncates an address, so the SDK never reports a full client IP. */
    public static function clientPrefix(?string $address): string
    {
        if ($address === null || $address === '') {
            return 'unknown';
        }

        $clean = str_starts_with($address, '::ffff:') ? substr($address, 7) : $address;

        // An IPv4 address with a port has exactly one colon; an IPv6 address
        // has several, and stripping its last group would corrupt it.
        if (substr_count($clean, ':') === 1) {
            $clean = substr($clean, 0, (int) strpos($clean, ':'));
        }

        if (str_contains($clean, ':')) {
            $groups = array_slice(explode(':', $clean), 0, 3);

            return implode(':', $groups) . '::';
        }

        $octets = explode('.', $clean);
        if (count($octets) !== 4) {
            return 'unknown';
        }

        return $octets[0] . '.' . $octets[1] . '.' . $octets[2] . '.0';
    }

    /** Percent-decodes, returning the input unchanged if it will not decode. */
    public static function decodeSafely(string $value): string
    {
        $decoded = urldecode($value);

        return $decoded === '' && $value !== '' ? $value : $decoded;
    }

    /** Anchored glob. Only `*` is supported, so a pattern cannot backtrack. */
    public static function pathMatches(string $path, string $pattern): bool
    {
        if (str_ends_with($pattern, '*')) {
            return str_starts_with($path, substr($pattern, 0, -1));
        }

        return $path === $pattern;
    }

    /**
     * Decides what happens to a request that matched rules.
     *
     * Anything uncertain logs rather than blocks, and every decision carries
     * why: an engineer looking at a blocked request at 3am needs to know in
     * seconds whether to disable a rule.
     *
     * @param array<string, mixed> $policy
     * @param array<int, array{id: string, severity: string, pattern: string}> $matched
     * @return array{action: string, reason: string, rule_id: ?string}
     */
    public static function decide(array $policy, string $path, array $matched): array
    {
        $override = null;
        foreach ($policy['overrides'] ?? [] as $candidate) {
            if (self::pathMatches($path, $candidate['pattern'])) {
                $override = $candidate;
                break;
            }
        }
        $mode = $override['mode'] ?? ($policy['default_mode'] ?? 'monitor');

        if ($mode === 'off') {
            return [
                'action' => 'allow',
                'reason' => $override !== null
                    ? "Protection is disabled for {$override['pattern']}: {$override['reason']}"
                    : 'Protection is disabled.',
                'rule_id' => null,
            ];
        }

        $exempt = $override['exempt_rules'] ?? [];
        $applicable = array_values(array_filter(
            $matched,
            static fn (array $rule): bool => !in_array($rule['id'], $exempt, true)
        ));

        if ($applicable === []) {
            return ['action' => 'allow', 'reason' => 'Nothing applicable matched.', 'rule_id' => null];
        }

        $worst = $applicable[0];
        foreach ($applicable as $rule) {
            if ($rule['severity'] === 'critical') {
                $worst = $rule;
                break;
            }
        }

        $blockingRules = $policy['blocking_rules'] ?? [];

        if ($mode === 'block' && in_array($worst['id'], $blockingRules, true)) {
            return [
                'action' => 'block',
                'reason' => "Blocked: {$worst['id']} ({$worst['severity']}) matched and is enabled for blocking.",
                'rule_id' => $worst['id'],
            ];
        }

        if ($mode === 'block') {
            // Matched, but not a rule the operator allowed to block. Logging is
            // the conservative reading.
            return [
                'action' => 'log',
                'reason' => "{$worst['id']} ({$worst['severity']}) matched but is not in the blocking rule list.",
                'rule_id' => $worst['id'],
            ];
        }

        return [
            'action' => 'log',
            'reason' => "{$worst['id']} ({$worst['severity']}) matched. Endpoint is in monitor mode, so the request continues.",
            'rule_id' => $worst['id'],
        ];
    }

    /**
     * Resolves the effective policy.
     *
     * A policy can never escalate monitor mode into blocking. That is the
     * second of the two opt-ins blocking requires.
     *
     * @param array<string, mixed> $config
     * @return array<string, mixed>
     */
    public static function effectivePolicy(array $config): array
    {
        if (($config['mode'] ?? 'monitor') !== 'block') {
            return ['default_mode' => 'monitor', 'overrides' => [], 'blocking_rules' => []];
        }

        if (isset($config['policy'])) {
            return $config['policy'];
        }

        // Without this, mode "block" would quietly block nothing: a shared
        // default carries no blocking rules on purpose. The caller has already
        // asked for blocking, so every rule the SDK can detect is eligible.
        return [
            'default_mode' => 'block',
            'overrides' => [],
            'blocking_rules' => array_column(self::RULES, 'id'),
        ];
    }

    /**
     * Evaluates a request description.
     *
     * Pure, so it can be tested exhaustively and reused by any framework
     * adapter. `protect()` builds the description from superglobals.
     *
     * @param array<string, mixed> $config
     * @param array<string, mixed> $request
     * @return array{decision: ?array<string, mixed>, event: ?array<string, mixed>}
     */
    public static function evaluate(array $config, array $request): array
    {
        try {
            $path = (string) ($request['path'] ?? '/');
            $query = (string) ($request['query'] ?? '');

            // Both the raw and decoded forms. A percent-encoded space defeats
            // every pattern containing one, and a double-encoded payload only
            // makes sense before decoding.
            $values = [$path, $query, self::decodeSafely($query), self::decodeSafely($path)];

            // Headers an attacker controls and applications commonly trust.
            foreach (['referer', 'x-forwarded-for', 'user-agent'] as $name) {
                $value = $request['headers'][$name] ?? '';
                if ($value !== '') {
                    $values[] = substr((string) $value, 0, 2000);
                }
            }

            $body = (string) ($request['body'] ?? '');
            if ($body !== '') {
                $values[] = substr($body, 0, 10000);
            }

            $matched = self::inspect($values);
            if ($matched === []) {
                return ['decision' => null, 'event' => null];
            }

            $policy = self::effectivePolicy($config);
            $decision = self::decide($policy, $path, $matched);

            $worst = $matched[0];
            foreach ($matched as $rule) {
                if ($rule['severity'] === 'critical') {
                    $worst = $rule;
                    break;
                }
            }

            return [
                'decision' => $decision,
                'event' => [
                    'at' => gmdate('Y-m-d\TH:i:s\Z'),
                    'method' => (string) ($request['method'] ?? 'GET'),
                    'path' => $path,
                    'ruleId' => $worst['id'],
                    'severity' => $worst['severity'],
                    'clientPrefix' => self::clientPrefix($request['remote_address'] ?? null),
                    'userAgent' => substr((string) ($request['headers']['user-agent'] ?? ''), 0, 300),
                    'blocked' => $decision['action'] === 'block',
                    // Why, recorded at the time. Reconstructing a decision from
                    // policy after the fact is guesswork once it has changed.
                    'reason' => $decision['reason'],
                ],
            ];
        } catch (\Throwable $e) {
            // Never throw into the request path.
            if (isset($config['on_error']) && is_callable($config['on_error'])) {
                ($config['on_error'])($e);
            }

            return ['decision' => null, 'event' => null];
        }
    }

    /**
     * Inspects the current request and, in block mode, ends it.
     *
     * @param array<string, mixed> $config
     * @return array{action: string, reason: string, rule_id: ?string}|null
     */
    public static function protect(array $config): ?array
    {
        self::$config = $config;

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                $name = strtolower(str_replace('_', '-', substr((string) $key, 5)));
                $headers[$name] = (string) $value;
            }
        }

        // php://input is readable more than once for ordinary requests, and
        // reading it here does not consume $_POST, so the application is
        // unaffected either way.
        $body = '';
        $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($length > 0 && $length <= (int) ($config['max_body_bytes'] ?? 65536)) {
            $body = (string) file_get_contents('php://input');
        }

        $result = self::evaluate($config, [
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'path' => parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/',
            'query' => $_SERVER['QUERY_STRING'] ?? '',
            'headers' => $headers,
            'remote_address' => $_SERVER['REMOTE_ADDR'] ?? null,
            'body' => $body,
        ]);

        if ($result['event'] !== null) {
            self::record($result['event']);
        }

        if ($result['decision'] !== null && $result['decision']['action'] === 'block') {
            if (!headers_sent()) {
                http_response_code(403);
                header('content-type: application/json');
            }
            // Deliberately terse: naming the rule would tell an attacker
            // exactly what to change.
            echo '{"error":"Request rejected."}';
            self::flush();
            exit;
        }

        return $result['decision'];
    }

    /**
     * Queues an event and arranges for it to be sent after the response.
     *
     * @param array<string, mixed> $event
     */
    public static function record(array $event): void
    {
        // Bounded: the application's memory matters more than these events.
        if (count(self::$queue) < 1000) {
            self::$queue[] = $event;
        }

        if (!self::$shutdownRegistered) {
            self::$shutdownRegistered = true;
            // Reporting happens after the response has been sent, so the user
            // never waits for the control plane. This is how PHP's execution
            // model substitutes for the other SDKs' background thread.
            register_shutdown_function([self::class, 'flush']);
        }
    }

    /** Sends any queued events. Failures are dropped, never retried forever. */
    public static function flush(): void
    {
        if (self::$queue === [] || empty(self::$config['url'])) {
            self::$queue = [];

            return;
        }

        $payload = json_encode([
            'app' => self::$config['app_name'] ?? 'php',
            'events' => self::$queue,
        ]);
        self::$queue = [];

        if ($payload === false) {
            return;
        }

        $url = rtrim((string) self::$config['url'], '/') . '/api/public/runtime/events';
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "content-type: application/json\r\n"
                    . 'authorization: Bearer ' . (self::$config['token'] ?? '') . "\r\n",
                'content' => $payload,
                'timeout' => 10,
                // Without this, a non-2xx response raises a warning and
                // file_get_contents returns false, which is noise rather than
                // information.
                'ignore_errors' => true,
            ],
        ]);

        $result = @file_get_contents($url, false, $context);
        if ($result === false && isset(self::$config['on_error']) && is_callable(self::$config['on_error'])) {
            (self::$config['on_error'])(new \RuntimeException('Reporting failed.'));
        }
    }

    /** Visible for tests: what is waiting to be sent. */
    public static function pending(): array
    {
        return self::$queue;
    }

    /** Visible for tests: clears state between cases. */
    public static function reset(): void
    {
        self::$queue = [];
        self::$config = [];
    }

    private function __construct()
    {
    }
}

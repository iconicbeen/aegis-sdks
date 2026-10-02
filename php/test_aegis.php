<?php

declare(strict_types=1);

/**
 * The PHP SDK, exercised through PHP's own built-in web server over real HTTP.
 *
 * Not by calling evaluate() directly: the failure modes that matter are a
 * request body the application can no longer read, a block that does not
 * actually stop execution, and reporting that makes the user wait. None of
 * those are visible from a unit call.
 *
 * No test framework, so the SDK has no dev dependency either. Run with:
 *
 *     php test_aegis.php
 */

require __DIR__ . '/src/Aegis.php';

use Aegis\Aegis;

// Cleared up front rather than only at the end: a previous run that exited
// early leaves these set, and the suite would then test a different
// configuration than it claims to. That produced a spurious failure once.
putenv('AEGIS_TEST_MODE=');
putenv('AEGIS_TEST_POLICY=');
putenv('AEGIS_TEST_COLLECTOR=');

$failures = 0;

function check(bool $condition, string $description): void
{
    global $failures;
    if (!$condition) {
        $failures++;
        echo "FAIL: {$description}\n";
    }
}

function same($actual, $expected, string $description): void
{
    global $failures;
    if ($actual !== $expected) {
        $failures++;
        echo "FAIL: {$description} (expected " . var_export($expected, true)
            . ', got ' . var_export($actual, true) . ")\n";
    }
}

const ATTACK = "1' UNION SELECT password FROM users";

// ---------------------------------------------------------------------------
// Real HTTP, via PHP's built-in server
// ---------------------------------------------------------------------------

/** Starts the built-in server against a router script and waits for it. */
function startServer(string $router, int $port): array
{
    $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $process = proc_open(
        sprintf('php -S 127.0.0.1:%d %s', $port, escapeshellarg($router)),
        $descriptors,
        $pipes
    );

    for ($i = 0; $i < 50; $i++) {
        usleep(100_000);
        $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
        if ($socket !== false) {
            fclose($socket);
            return [$process, $pipes];
        }
    }

    // Reached only when the port never opened. Saying so beats a wall of
    // "expected 200, got 0" that looks like a detection failure.
    echo "WARNING: server on port {$port} did not start\n";

    return [$process, $pipes];
}

function stopServer($process, array $pipes): void
{
    foreach ($pipes as $pipe) {
        if (is_resource($pipe)) {
            fclose($pipe);
        }
    }
    if (is_resource($process)) {
        proc_terminate($process, SIGTERM);
        proc_close($process);
    }
}

/** @return array{status: int, body: string} */
function request(int $port, string $path, ?string $body = null): array
{
    $options = [
        'http' => [
            'method' => $body === null ? 'GET' : 'POST',
            'timeout' => 5,
            // Without this a 403 raises a warning and returns false, which is
            // exactly the response under test.
            'ignore_errors' => true,
            'header' => "content-type: application/json\r\n",
        ],
    ];
    if ($body !== null) {
        $options['http']['content'] = $body;
    }

    $result = @file_get_contents(
        "http://127.0.0.1:{$port}{$path}",
        false,
        stream_context_create($options)
    );

    $status = 0;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('#^HTTP/\S+\s+(\d+)#', $header, $m) === 1) {
            $status = (int) $m[1];
        }
    }

    return ['status' => $status, 'body' => $result === false ? '' : $result];
}

// A router that installs the firewall and then echoes the request body, so a
// body the application can no longer read is visible.
$router = <<<'PHP'
<?php
require __DIR__ . '/src/Aegis.php';

$mode = getenv('AEGIS_TEST_MODE') ?: 'monitor';
$config = [
    'url' => getenv('AEGIS_TEST_COLLECTOR') ?: '',
    'token' => 'test-token',
    'app_name' => 'php-test',
    'mode' => $mode,
];

if (getenv('AEGIS_TEST_POLICY') === 'exempt') {
    $config['policy'] = [
        'default_mode' => 'block',
        'overrides' => [[
            'pattern' => '/webhooks/*',
            'mode' => 'monitor',
            'reason' => 'Third-party payloads look like attacks and we do not control them.',
            'exempt_rules' => [],
        ]],
        'blocking_rules' => ['sqli-union', 'command-injection'],
    ];
}

\Aegis\Aegis::protect($config);

// Reached only when the firewall allowed the request through.
$body = (string) file_get_contents('php://input');
header('content-type: application/json');
echo json_encode(['ok' => true, 'received' => $body]);
PHP;

$routerPath = __DIR__ . '/test_router.php';
file_put_contents($routerPath, $router);

// A collector that records what the SDK actually sends.
$collectorPath = __DIR__ . '/test_collector.php';
file_put_contents($collectorPath, <<<'PHP'
<?php
$body = (string) file_get_contents('php://input');
file_put_contents(__DIR__ . '/test_events.log', $body . "\n", FILE_APPEND);
header('content-type: application/json');
echo '{}';
PHP);

@unlink(__DIR__ . '/test_events.log');

// ---------------------------------------------------------------------------
// Monitor mode
// ---------------------------------------------------------------------------

putenv('AEGIS_TEST_MODE=monitor');
putenv('AEGIS_TEST_COLLECTOR=http://127.0.0.1:8712');
[$collector, $collectorPipes] = startServer($collectorPath, 8712);
[$server, $pipes] = startServer($routerPath, 8711);

$clean = request(8711, '/search?q=hello');
same($clean['status'], 200, 'a clean request passes');
check(str_contains($clean['body'], '"ok":true'), 'the application handled it');

// Monitor is the default precisely so that installing the SDK cannot itself
// cause an outage.
$attack = request(8711, '/api?q=' . rawurlencode(ATTACK));
same($attack['status'], 200, 'monitor mode must not block');

// The body is read for inspection and the application must still get it. In
// PHP that means php://input has to remain readable.
$posted = request(8711, '/submit', '{"name": "hello world"}');
same($posted['status'], 200, 'a clean POST passes');
check(
    str_contains($posted['body'], 'hello world'),
    'the application still receives its body'
);

usleep(500_000);
$events = @file_get_contents(__DIR__ . '/test_events.log') ?: '';
check($events !== '', 'monitor mode still reports the attack');
check(str_contains($events, 'sqli-union'), 'the report names the rule');
check(str_contains($events, '"blocked":false'), 'monitor mode records it as not blocked');
check(
    str_contains(strtolower($events), 'monitor'),
    'the reason explains why it was not blocked'
);
// A full client IP is personal data the control plane has no use for.
check(
    !str_contains($events, '"clientPrefix":"127.0.0.1"'),
    'the client address is truncated, not sent whole'
);

stopServer($server, $pipes);

// ---------------------------------------------------------------------------
// Block mode
// ---------------------------------------------------------------------------

// The regression this guards: a default policy carries no blocking rules on
// purpose, so mode "block" would quietly block nothing.
putenv('AEGIS_TEST_MODE=block');
[$server, $pipes] = startServer($routerPath, 8713);

$blocked = request(8713, '/api?q=' . rawurlencode(ATTACK));
same($blocked['status'], 403, 'block mode with no policy actually blocks');
check(str_contains($blocked['body'], 'Request rejected'), 'the rejection body is terse');
// Naming the rule would tell an attacker exactly what to change.
check(!str_contains($blocked['body'], 'sqli-union'), 'the rejection reveals no rule');
// A blocked request must not reach the application at all.
check(!str_contains($blocked['body'], '"ok":true'), 'the application was never reached');

same(request(8713, '/search?q=hello')['status'], 200, 'clean traffic still passes in block mode');
// The bug found in the Python port: a query string arrives percent-encoded, so
// %20 defeats every pattern containing a space.
same(
    request(8713, '/x?q=' . rawurlencode('; cat /etc/shadow'))['status'],
    403,
    'an encoded payload is still detected'
);
same(
    request(8713, '/api', '{"q":"' . ATTACK . '"}')['status'],
    403,
    'an attack in the body is blocked'
);

stopServer($server, $pipes);

// ---------------------------------------------------------------------------
// Per-endpoint policy
// ---------------------------------------------------------------------------

putenv('AEGIS_TEST_POLICY=exempt');
[$server, $pipes] = startServer($routerPath, 8714);

same(request(8714, '/api?q=' . rawurlencode(ATTACK))['status'], 403, 'protected path blocks');
// Same payload, different outcome: that is the point of per-endpoint policy.
// Without it the only way to stop blocking one misfiring endpoint is to stop
// blocking everywhere.
same(
    request(8714, '/webhooks/stripe?q=' . rawurlencode(ATTACK))['status'],
    200,
    'the exempt endpoint passes the same attack'
);

stopServer($server, $pipes);
putenv('AEGIS_TEST_POLICY=');

// ---------------------------------------------------------------------------
// Monitor mode cannot be escalated
// ---------------------------------------------------------------------------

putenv('AEGIS_TEST_MODE=monitor');
putenv('AEGIS_TEST_POLICY=exempt');
[$server, $pipes] = startServer($routerPath, 8715);

// Blocking takes two separate opt-ins, and this is the second missing.
same(
    request(8715, '/api?q=' . rawurlencode(ATTACK))['status'],
    200,
    'a policy must not escalate monitor mode'
);

stopServer($server, $pipes);
stopServer($collector, $collectorPipes);

putenv('AEGIS_TEST_MODE=');
putenv('AEGIS_TEST_POLICY=');
putenv('AEGIS_TEST_COLLECTOR=');

// ---------------------------------------------------------------------------
// Pure decisions
// ---------------------------------------------------------------------------

check(Aegis::pathMatches('/webhooks/stripe', '/webhooks/*'), 'a glob matches its prefix');
check(Aegis::pathMatches('/api', '/api'), 'an exact pattern matches itself');
// A prefix that is not a glob must not match by accident.
check(!Aegis::pathMatches('/api/v2', '/api'), 'exact patterns do not match longer paths');
// And a pattern must not match something merely containing it.
check(!Aegis::pathMatches('/public/webhooks/x', '/webhooks/*'), 'globs are anchored');

same(Aegis::clientPrefix('192.0.2.44:54321'), '192.0.2.0', 'IPv4 with a port');
same(Aegis::clientPrefix('192.0.2.44'), '192.0.2.0', 'bare IPv4');
same(Aegis::clientPrefix('::ffff:192.0.2.44'), '192.0.2.0', 'IPv4-mapped IPv6');
same(Aegis::clientPrefix(null), 'unknown', 'a missing address');
same(Aegis::clientPrefix('2001:db8:85a3::8a2e'), '2001:db8:85a3::', 'IPv6');

$policy = ['default_mode' => 'block', 'overrides' => [], 'blocking_rules' => ['command-injection']];
$matched = array_values(array_filter(
    Aegis::RULES,
    static fn (array $r): bool => $r['id'] === 'sqli-union'
));
$decision = Aegis::decide($policy, '/api', $matched);
// Matched but not authorised to block: the conservative reading.
same($decision['action'], 'log', 'an unauthorised rule logs rather than blocks');
check(
    str_contains($decision['reason'], 'not in the blocking rule list'),
    'the reason explains itself'
);

$exemptPolicy = [
    'default_mode' => 'block',
    'overrides' => [[
        'pattern' => '/import',
        'mode' => 'block',
        'reason' => 'Bulk import.',
        'exempt_rules' => ['sqli-union'],
    ]],
    'blocking_rules' => ['sqli-union'],
];
same(Aegis::decide($exemptPolicy, '/import', $matched)['action'], 'allow', 'an exempt rule allows');

// ---------------------------------------------------------------------------

@unlink($routerPath);
@unlink($collectorPath);
@unlink(__DIR__ . '/test_events.log');

if ($failures > 0) {
    echo "{$failures} assertion(s) failed\n";
    exit(1);
}
echo "all PHP SDK tests passed\n";

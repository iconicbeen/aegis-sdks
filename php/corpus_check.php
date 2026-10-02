<?php
// Prints this SDK's verdict for each corpus case, so the shared parity test can
// compare PHP against the other SDKs.
declare(strict_types=1);
require __DIR__ . '/src/Aegis.php';

$cases = json_decode((string) file_get_contents('php://stdin'), true);
$out = [];
foreach ($cases as $case) {
    $ids = [];
    foreach (\Aegis\Aegis::RULES as $rule) {
        if (preg_match($rule['pattern'], $case) === 1) {
            $ids[] = $rule['id'];
        }
    }
    sort($ids);
    $out[$case] = $ids;
}
echo json_encode($out, JSON_UNESCAPED_SLASHES), "\n";

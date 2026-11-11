<?php
declare(strict_types=1);

// Read-only PHP CLI diagnostics. Do not add config writes or shell execution here.
$result = [
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'os' => PHP_OS,
    'simplexml_available' => extension_loaded('simplexml'),
    'loaded_extensions' => [
        'openssl' => extension_loaded('openssl'),
        'json' => extension_loaded('json'),
        'simplexml' => extension_loaded('simplexml'),
    ],
];

echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

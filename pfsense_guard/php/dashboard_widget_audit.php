<?php
declare(strict_types=1);

// Read-only, deliberately low-detail inspection of /conf/config.xml.
// It never prints feed URLs, credentials, certificates, or other configuration values.
$configPath = '/conf/config.xml';
$result = [
    'config_readable' => is_readable($configPath),
    'widgets_section_present' => false,
    'widget_sequence_present' => false,
    'rss_reference_detected' => false,
    'parse_error' => null,
];

if (!is_readable($configPath)) {
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit(0);
}

libxml_use_internal_errors(true);
$xml = simplexml_load_file($configPath, SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOBLANKS);
if ($xml === false) {
    $result['parse_error'] = 'Unable to parse config.xml as XML';
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit(0);
}

if (isset($xml->widgets)) {
    $result['widgets_section_present'] = true;
    $result['widget_sequence_present'] = isset($xml->widgets->sequence);
    $widgetXml = $xml->widgets->asXML() ?: '';
    $result['rss_reference_detected'] = stripos($widgetXml, 'rss') !== false;
}

echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

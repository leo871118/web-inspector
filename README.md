# WebInspector PHP

Framework-agnostic PHP 8.3+ library for automated website technical auditing, HTTP security headers grading, cookie security inspection, SSL/TLS X.509 parsing, DNS/email anti-spoofing checks, technology stack fingerprinting, and WordPress diagnostics.

## Features

- **SSRF-Safe HTTP Client**: Native cURL client enforcing IPv4 resolution, redirect tracking, and private/loopback network blocking (`UrlNormalizer`, `SafeHttpClient`).
- **HTTP Security Headers Audit**: Evaluates HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` with a normalized `0–100` score and letter grade (`A+` to `F`).
- **Cookie Security Audit**: Inspects `Set-Cookie` headers for `Secure`, `HttpOnly`, and `SameSite` attributes with automatic value masking.
- **SSL/TLS Certificate Inspection**: Connects over port `443` to extract X.509 issuer, validity dates, remaining days, and Subject Alternative Names (SAN).
- **DNS & Email Security**: Resolves `A`, `AAAA`, `PTR`, `NS`, `MX`, `SPF`, `DMARC`, and `CAA` records (with DNS-over-HTTPS fallback) and identifies hosting and mail providers.
- **On-Page SEO & DOM Performance**: Extracts `<title>`, meta description, canonical alignment, `<h1>` headings, Open Graph, Twitter Cards, Schema.org JSON-LD entities, third-party hosts, lazy-loading coverage, and mixed content.
- **Stack Fingerprinting**: Detects CMS platforms, backend runtimes, frontend libraries (flagging outdated jQuery versions), CDN/WAF layers, CMP cookie banners, and analytics trackers.
- **WordPress Diagnostics**: Detects WordPress core version, active/child theme metadata, plugins (HTML assets + REST API namespaces), and hardening vectors (`/wp-json/wp/v2/users`, `/?author=1`, `/xmlrpc.php`, `/wp-content/debug.log`, `/wp-admin/install.php`).
- **Optional AI Executive Summary**: Decoupled `GeminiSummarizer` adapter to turn any `AuditReport` into a concise operational action plan.

## Requirements

- PHP `^8.3`
- Extensions: `ext-curl`, `ext-dom`, `ext-json`, `ext-mbstring`, `ext-openssl`

## Installation

```bash
composer require leandroperez/web-inspector
```

## Quick Start

### 1. Complete Website Audit

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use LeandroPerez\WebInspector\Config\InspectorConfig;
use LeandroPerez\WebInspector\WebInspector;

$config = new InspectorConfig(
    defaultTimeout: 8.0,
    probeTimeout: 4.0,
    blockPrivateNetworks: true,
);

$inspector = new WebInspector($config);
$report =$inspector->inspect('example.com');

echo "Status: {$report->statusCode} ({$report->responseTimeMs} ms)\n";
echo "Security Grade: {$report->securityHeaders->grade} ({$report->securityHeaders->score}/100)\n";
echo "CMS: {$report->stack->cmsName}\n";

foreach ($report->getAllFindings() as$finding) {
    echo "[{$finding->severity->value}] {$finding->title}: {$finding->detail}\n";
}

// Serialize full report to JSON
$json = json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
```

### 2. Using Individual Analyzers

Every analyzer is decoupled and can be used standalone:

```php
<?php

declare(strict_types=1);

use LeandroPerez\WebInspector\Analyzer\DnsNetworkAnalyzer;
use LeandroPerez\WebInspector\Analyzer\SecurityHeadersAnalyzer;
use LeandroPerez\WebInspector\Http\SafeHttpClient;

$client = new SafeHttpClient();
$response =$client->get('https://example.com/');

$headersReport = (new SecurityHeadersAnalyzer())->analyze($response);
echo "Headers Grade: {$headersReport->grade}\n";

$dnsReport = (new DnsNetworkAnalyzer($client))->analyze('example.com');
echo "Hosting: {$dnsReport->hostingProvider} \vert{} DMARC: {$dnsReport->dmarcPolicy}\n";
```

### 3. Optional AI Diagnostic Summary (Google Gemini)

```php
<?php

declare(strict_types=1);

use LeandroPerez\WebInspector\Ai\GeminiSummarizer;
use LeandroPerez\WebInspector\WebInspector;

$report = (new WebInspector())->inspect('example.com');

$summarizer = new GeminiSummarizer(
    apiKey: $_ENV['GEMINI_API_KEY'],
    model: 'gemini-2.5-flash',
);

$summaryMarkdown = $summarizer->summarize($report, language: 'en');
echo $summaryMarkdown;
```

## Local Web Demo

A standalone web demo is included in `examples/index.php`. Start the built-in PHP server from the project root:

```bash
php -S localhost:8080 -t examples
```

Then open `http://localhost:8080` in your browser.

## Quality & Testing

```bash
composer test      # Run PHPUnit offline test suite
composer stan      # Run PHPStan static analysis (Level 8)
composer cs-check  # Check @PER-CS coding style compliance
```

## License

This project is open-source software licensed under the [MIT License](LICENSE).
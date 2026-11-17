<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Core;

use LeandroPerez\WebInspector\Analyzer\DnsNetworkAnalyzer;
use LeandroPerez\WebInspector\Analyzer\SslCertificateAnalyzer;
use LeandroPerez\WebInspector\Analyzer\WordPressAnalyzer;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Dto\MxRecord;
use LeandroPerez\WebInspector\WebInspector;
use PHPUnit\Framework\TestCase;

final class WebInspectorTest extends TestCase
{
    public function testAssemblesCompleteAuditReportAndSerializesToJson(): void
    {
        $html = <<<'HTML'
            <!doctype html>
            <html>
            <head>
                <title>Test Agency</title>
                <meta name="description" content="Web engineering studio.">
                <meta name="generator" content="WordPress 6.7.1">
            </head>
            <body><h1>Hello World</h1></body>
            </html>
            HTML;

        $response = new HttpResponse(
            statusCode: 200,
            initialStatusCode: 200,
            effectiveUrl: 'https://example.org/',
            body: $html,
            headers: [
                'strict-transport-security' => ['max-age=31536000'],
                'x-frame-options' => ['SAMEORIGIN'],
                'x-content-type-options' => ['nosniff'],
            ],
            rawCookies: ['session_id=123456789; Path=/; Secure; HttpOnly; SameSite=Lax'],
            redirectCount: 0,
            durationMs: 140,
            protocolVersion: 'HTTP/2',
        );

        $dnsReport = (new DnsNetworkAnalyzer())->buildReport(
            ipv4: '93.184.216.34',
            ipv6Records: [],
            reverseDns: null,
            apexDomain: 'example.org',
            nameservers: ['ns1.example.org'],
            mxRecords: [new MxRecord('mail.example.org', 10)],
            primaryMxPtr: null,
            spfRaw: 'v=spf1 -all',
            dmarcRaw: 'v=DMARC1; p=reject',
            caaRecords: ['0 issue "letsencrypt.org"'],
        );

        $now = 1_760_000_000;
        $sslReport = (new SslCertificateAnalyzer())->analyzeParsedCertificate([
            'issuer' => ['O' => "Let's Encrypt"],
            'validFrom_time_t' => $now - 86400,
            'validTo_time_t' => $now + (60 * 86400),
        ], $now);

        $wpReport = (new WordPressAnalyzer())->analyzeFromResponses($html);

        $report = (new WebInspector())->assembleReport(
            targetUrl: 'https://example.org/',
            response: $response,
            dnsReport: $dnsReport,
            sslReport: $sslReport,
            wpReport: $wpReport,
        );

        $json = json_encode($report, JSON_THROW_ON_ERROR);
        $decoded = json_decode($json, true);

        self::assertIsArray($decoded);
        self::assertSame(200, $decoded['status_code']);
        self::assertTrue($decoded['wordpress']['is_wordpress']);
        self::assertSame(0, $decoded['summary']['errors']);
    }
}

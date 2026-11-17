<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Analyzer;

use LeandroPerez\WebInspector\Analyzer\SslCertificateAnalyzer;
use LeandroPerez\WebInspector\Dto\Severity;
use PHPUnit\Framework\TestCase;

final class SslCertificateAnalyzerTest extends TestCase
{
    private SslCertificateAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new SslCertificateAnalyzer();
    }

    public function testParsesValidCertificateWithSanDomains(): void
    {
        $now = 1_760_000_000;
        $report = $this->analyzer->analyzeParsedCertificate([
            'issuer' => ['O' => "Let's Encrypt", 'CN' => 'R11'],
            'subject' => ['CN' => 'example.com'],
            'validFrom_time_t' => $now - (10 * 86400),
            'validTo_time_t' => $now + (60 * 86400),
            'extensions' => [
                'subjectAltName' => 'DNS:example.com, DNS:www.example.com, IP Address:93.184.216.34',
            ],
        ], $now);

        self::assertTrue($report->valid);
        self::assertFalse($report->expired);
        self::assertSame("Let's Encrypt", $report->issuer);
        self::assertSame(60, $report->daysRemaining);
        self::assertSame(['example.com', 'www.example.com'], $report->sanDomains);
        self::assertSame([], $report->findings);
    }

    public function testEmitsWarningWhenCertificateExpiresWithin15Days(): void
    {
        $now = 1_760_000_000;
        $report = $this->analyzer->analyzeParsedCertificate([
            'issuer' => ['O' => 'Google Trust Services'],
            'validFrom_time_t' => $now - (80 * 86400),
            'validTo_time_t' => $now + (7 * 86400),
        ], $now);

        self::assertTrue($report->valid);
        self::assertSame(7, $report->daysRemaining);
        self::assertCount(1, $report->findings);
        self::assertSame(Severity::Warning, $report->findings[0]->severity);
    }
}

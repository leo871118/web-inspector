<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Analyzer;

use LeandroPerez\WebInspector\Analyzer\CookieAuditAnalyzer;
use PHPUnit\Framework\TestCase;

final class CookieAuditAnalyzerTest extends TestCase
{
    private CookieAuditAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new CookieAuditAnalyzer();
    }

    public function testScores100WhenAllCookiesHaveFullSecurityFlags(): void
    {
        $report = $this->analyzer->analyzeRawCookies([
            '__Host-session=abcdef1234567890; Path=/; Secure; HttpOnly; SameSite=Strict',
        ], true);

        self::assertSame(1, $report->totalCount);
        self::assertSame(100, $report->securityScore);
        self::assertSame('abc***', $report->cookies[0]->maskedValue);
        self::assertSame([], $report->findings);
    }

    public function testFlagsMissingSecureHttpOnlyAndInvalidSameSiteNone(): void
    {
        $report = $this->analyzer->analyzeRawCookies([
            'tracker_id=987654321; Path=/; SameSite=None',
        ], true);

        self::assertSame(1, $report->totalCount);
        self::assertSame(25, $report->securityScore);
        self::assertCount(3, $report->findings);
    }
}

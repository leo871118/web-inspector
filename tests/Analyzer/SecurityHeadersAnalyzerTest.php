<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Analyzer;

use LeandroPerez\WebInspector\Analyzer\SecurityHeadersAnalyzer;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use PHPUnit\Framework\TestCase;

final class SecurityHeadersAnalyzerTest extends TestCase
{
    private SecurityHeadersAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new SecurityHeadersAnalyzer();
    }

    public function testAwardsGradeAPlusWhenAllSecurityHeadersArePresent(): void
    {
        $response = new HttpResponse(
            statusCode: 200,
            initialStatusCode: 200,
            effectiveUrl: 'https://example.com/',
            body: '<html></html>',
            headers: [
                'strict-transport-security' => ['max-age=31536000; includeSubDomains; preload'],
                'content-security-policy' => ["default-src 'self'"],
                'x-frame-options' => ['SAMEORIGIN'],
                'x-content-type-options' => ['nosniff'],
                'referrer-policy' => ['strict-origin-when-cross-origin'],
                'permissions-policy' => ['geolocation=()'],
            ],
            rawCookies: [],
            redirectCount: 0,
            durationMs: 120,
        );

        $report = $this->analyzer->analyze($response);

        self::assertSame(100, $report->score);
        self::assertSame('A+', $report->grade);
        self::assertSame([], $report->findings);
        self::assertTrue($report->headers['hsts']->meta['preload']);
    }

    public function testAssignsGradeFAndEmitsFindingsWhenHeadersAreMissing(): void
    {
        $response = new HttpResponse(
            statusCode: 200,
            initialStatusCode: 200,
            effectiveUrl: 'https://example.com/',
            body: '<html></html>',
            headers: [],
            rawCookies: [],
            redirectCount: 0,
            durationMs: 95,
        );

        $report = $this->analyzer->analyze($response);

        self::assertSame(0, $report->score);
        self::assertSame('F', $report->grade);
        self::assertCount(4, $report->findings);
    }
}

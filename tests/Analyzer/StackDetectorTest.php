<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Analyzer;

use LeandroPerez\WebInspector\Analyzer\StackDetector;
use PHPUnit\Framework\TestCase;

final class StackDetectorTest extends TestCase
{
    public function testDetectsCmsOutdatedJqueryAndExternalGoogleFonts(): void
    {
        $html = <<<'HTML'
            <html>
            <head>
                <meta name="generator" content="WordPress 6.7.1">
                <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
                <script src="https://example.com/wp-includes/js/jquery/jquery-1.12.4.min.js"></script>
                <script src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234567"></script>
            </head>
            <body></body>
            </html>
            HTML;

        $report = (new StackDetector())->detect($html, ['server' => ['cloudflare']], null, ['ns1.cloudflare.com']);

        self::assertSame('WordPress', $report->cmsName);
        self::assertSame('6.7.1', $report->cmsVersion);
        self::assertContains('Cloudflare', $report->cdnWaf);
        self::assertSame('jQuery', $report->frontendLibraries[0]['name']);
        self::assertTrue($report->frontendLibraries[0]['outdated']);
        self::assertCount(2, $report->findings);
    }
}

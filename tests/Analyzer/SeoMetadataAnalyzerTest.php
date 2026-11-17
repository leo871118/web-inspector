<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Analyzer;

use LeandroPerez\WebInspector\Analyzer\SeoMetadataAnalyzer;
use PHPUnit\Framework\TestCase;

final class SeoMetadataAnalyzerTest extends TestCase
{
    public function testExtractsSeoTagsSocialCardsAndSchemaEntities(): void
    {
        $html = <<<'HTML'
            <!doctype html>
            <html>
            <head>
                <title>Example Store — Official Site</title>
                <meta name="description" content="Shop high performance gear online.">
                <link rel="canonical" href="https://example.com/">
                <meta property="og:title" content="Example Store">
                <meta property="og:image" content="https://example.com/og.jpg">
                <meta name="twitter:card" content="summary_large_image">
                <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Example"}</script>
            </head>
            <body><h1>Welcome to Example Store</h1></body>
            </html>
            HTML;

        $report = (new SeoMetadataAnalyzer())->analyzeHtml($html, 'https://example.com/');

        self::assertSame('Example Store — Official Site', $report->title);
        self::assertFalse($report->canonicalMismatch);
        self::assertSame(1, $report->h1Count);
        self::assertTrue($report->openGraph['present']);
        self::assertSame('summary_large_image', $report->twitterCard['card']);
        self::assertSame(['Organization'], $report->schemaTypes);
        self::assertSame([], $report->findings);
    }
}

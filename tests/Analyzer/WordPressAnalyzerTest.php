<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Analyzer;

use LeandroPerez\WebInspector\Analyzer\WordPressAnalyzer;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use PHPUnit\Framework\TestCase;

final class WordPressAnalyzerTest extends TestCase
{
    public function testAuditsWordPressCoreThemePluginsAndExposedHardeningVectors(): void
    {
        $html = <<<'HTML'
            <html>
            <head>
                <meta name="generator" content="WordPress 6.7.1">
                <link rel="stylesheet" href="https://example.com/wp-content/themes/astra/style.css?ver=4.8.0">
                <script src="https://example.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9.8"></script>
            </head>
            <body></body>
            </html>
            HTML;

        $restResp = new HttpResponse(200, 200, 'https://example.com/wp-json/', '{"namespaces":["wp/v2","yoast/v1"]}', [], [], 0, 50);
        $usersResp = new HttpResponse(200, 200, 'https://example.com/wp-json/wp/v2/users', '[{"slug":"admin"}]', [], [], 0, 40);
        $authorResp = new HttpResponse(301, 301, 'https://example.com/?author=1', '', ['location' => ['https://example.com/author/admin/']], [], 0, 35);

        $report = (new WordPressAnalyzer())->analyzeFromResponses(
            html: $html,
            restResponse: $restResp,
            usersResponse: $usersResp,
            authorEnumResponse: $authorResp,
            themeStyleBody: "Theme Name: Astra\nVersion: 4.8.0\nAuthor: Brainstorm Force\n",
        );

        self::assertTrue($report->isWordPress);
        self::assertSame('6.7.1', $report->version);
        self::assertSame('Astra', $report->theme['name']);
        self::assertCount(2, $report->plugins);
        self::assertTrue($report->hardening['rest_users_exposed']);
        self::assertTrue($report->hardening['author_enum_exposed']);
        self::assertCount(2, $report->findings);
    }
}

<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Ai;

use LeandroPerez\WebInspector\Ai\GeminiSummarizer;
use LeandroPerez\WebInspector\Analyzer\DnsNetworkAnalyzer;
use LeandroPerez\WebInspector\Analyzer\SslCertificateAnalyzer;
use LeandroPerez\WebInspector\Analyzer\WordPressAnalyzer;
use LeandroPerez\WebInspector\Dto\HttpResponse;
use LeandroPerez\WebInspector\Exception\InspectorException;
use LeandroPerez\WebInspector\WebInspector;
use PHPUnit\Framework\TestCase;

final class GeminiSummarizerTest extends TestCase
{
    public function testThrowsExceptionWhenApiKeyIsEmpty(): void
    {
        $response = new HttpResponse(200, 200, 'https://example.com/', '<html></html>', [], [], 0, 50);
        $dns = (new DnsNetworkAnalyzer())->buildReport('93.184.216.34', [], null, 'example.com', [], [], null, null, null, []);
        $ssl = (new SslCertificateAnalyzer())->analyze('example.com', false);
        $wp = (new WordPressAnalyzer())->analyzeFromResponses('<html></html>');
        $report = (new WebInspector())->assembleReport('https://example.com/', $response, $dns, $ssl, $wp);

        $summarizer = new GeminiSummarizer('   ');

        $this->expectException(InspectorException::class);
        $summarizer->summarize($report);
    }
}

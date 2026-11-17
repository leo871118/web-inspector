<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Http;

use LeandroPerez\WebInspector\Exception\InspectorException;
use LeandroPerez\WebInspector\Exception\SsrfBlockedException;
use LeandroPerez\WebInspector\Http\UrlNormalizer;
use PHPUnit\Framework\TestCase;

final class UrlNormalizerTest extends TestCase
{
    private UrlNormalizer $normalizer;

    protected function setUp(): void
    {
        $this->normalizer = new UrlNormalizer();
    }

    public function testNormalizesBareDomainToHttps(): void
    {
        $result = $this->normalizer->normalize('  Example.COM  ');

        self::assertSame('https://example.com/', $result['url']);
        self::assertSame('example.com', $result['host']);
        self::assertSame('https', $result['scheme']);
    }

    public function testRejectsEmptyInput(): void
    {
        $this->expectException(InspectorException::class);
        $this->normalizer->normalize('   ');
    }

    public function testBlocksLoopbackAndPrivateIps(): void
    {
        $this->expectException(SsrfBlockedException::class);
        $this->normalizer->assertPublicHost('127.0.0.1');
    }

    public function testBlocksLocalhostHostname(): void
    {
        $this->expectException(SsrfBlockedException::class);
        $this->normalizer->assertPublicHost('localhost');
    }
}

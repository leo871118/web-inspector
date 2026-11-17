<?php

declare(strict_types=1);

namespace LeandroPerez\WebInspector\Tests\Analyzer;

use LeandroPerez\WebInspector\Analyzer\DnsNetworkAnalyzer;
use LeandroPerez\WebInspector\Dto\MxRecord;
use PHPUnit\Framework\TestCase;

final class DnsNetworkAnalyzerTest extends TestCase
{
    private DnsNetworkAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new DnsNetworkAnalyzer();
    }

    public function testExtractsApexDomainAcrossStandardAndMultiLevelTlds(): void
    {
        self::assertSame('example.it', $this->analyzer->extractApexDomain('www.shop.example.it'));
        self::assertSame('gymshark.co.uk', $this->analyzer->extractApexDomain('uk.gymshark.co.uk'));
    }

    public function testDetectsProvidersAndEvaluatesCompleteEmailSecurity(): void
    {
        $report = $this->analyzer->buildReport(
            ipv4: '62.149.128.40',
            ipv6Records: ['2001:db8::1'],
            reverseDns: 'webx123.aruba.it',
            apexDomain: 'example.it',
            nameservers: ['dns.technorail.com', 'dns2.technorail.com'],
            mxRecords: [new MxRecord('aspmx.l.google.com', 1)],
            primaryMxPtr: null,
            spfRaw: 'v=spf1 include:_spf.google.com -all',
            dmarcRaw: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.it',
            caaRecords: ['0 issue "letsencrypt.org"'],
        );

        self::assertSame('Aruba Hosting / Cloud', $report->hostingProvider);
        self::assertSame('Google Workspace', $report->mailProvider);
        self::assertSame('reject', $report->dmarcPolicy);
        self::assertSame([], $report->findings);
    }
}

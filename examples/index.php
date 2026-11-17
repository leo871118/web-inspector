<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use LeandroPerez\WebInspector\Dto\Severity;
use LeandroPerez\WebInspector\WebInspector;

$target = trim((string) ($_GET['url'] ?? ''));
$report = null;
$reportJson = null;
$error = null;

if ($target !== '') {
    try {
        $inspector = new WebInspector();
        $report = $inspector->inspect($target);
        $reportJson = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    } catch (\Throwable $e) {
        $error = $e->getMessage();
    }
}

$esc = static fn(mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$gradeColor = static fn(string $grade): string => match ($grade) {
    'A+', 'A' => 'badge-green',
    'B' => 'badge-blue',
    'C', 'D' => 'badge-amber',
    default => 'badge-red',
};
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WebInspector PHP — Technical Site Audit</title>
    <style>
        :root {
            --bg: #0b1120;
            --surface: #111827;
            --surface-alt: #0f172a;
            --border: #1e293b;
            --text: #f1f5f9;
            --muted: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }
        .container { max-width: 1180px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
        header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.5rem; }
        .brand h1 { margin: 0; font-size: 1.5rem; letter-spacing: -0.02em; display: flex; align-items: center; gap: .6rem; }
        .brand p { margin: .25rem 0 0; color: var(--muted); font-size: .9rem; }
        .search-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: .85rem;
            padding: 1.25rem;
            margin-bottom: 1.75rem;
        }
        .search-form { display: flex; gap: .65rem; flex-wrap: wrap; }
        .search-input {
            flex: 1;
            min-width: 240px;
            padding: .75rem 1rem;
            border-radius: .55rem;
            border: 1px solid #334155;
            background: var(--surface-alt);
            color: var(--text);
            font-size: .95rem;
        }
        .search-input:focus { outline: none; border-color: var(--accent); }
        .btn-primary {
            padding: .75rem 1.4rem;
            border-radius: .55rem;
            border: 0;
            background: var(--accent);
            color: #fff;
            font-weight: 600;
            font-size: .95rem;
            cursor: pointer;
        }
        .btn-primary:hover { background: var(--accent-hover); }
        .presets { margin-top: .75rem; display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; font-size: .8rem; color: var(--muted); }
        .preset-link {
            color: #cbd5e1;
            text-decoration: none;
            background: var(--surface-alt);
            border: 1px solid var(--border);
            padding: .2rem .6rem;
            border-radius: .4rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        }
        .preset-link:hover { border-color: var(--accent); color: #fff; }
        .alert-error {
            background: rgba(127, 29, 29, .35);
            border: 1px solid #991b1b;
            color: #fecaca;
            padding: 1rem 1.25rem;
            border-radius: .75rem;
            margin-bottom: 1.5rem;
        }
        .hero-bar {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: .85rem;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.5rem;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
        }
        .hero-url { font-size: 1.15rem; font-weight: 700; color: #fff; word-break: break-all; text-decoration: none; }
        .hero-url:hover { color: #60a5fa; }
        .hero-meta { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .45rem; }
        .metrics-strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .75rem; margin-bottom: 1.5rem; }
        .metric-box {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: .75rem;
            padding: .9rem 1rem;
        }
        .metric-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); font-weight: 700; }
        .metric-value { font-size: 1.25rem; font-weight: 800; margin-top: .2rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(460px, 1fr)); gap: 1.25rem; margin-bottom: 1.5rem; }
        @media (max-width: 540px) { .grid-2 { grid-template-columns: 1fr; } }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: .85rem;
            padding: 1.25rem 1.4rem;
        }
        .card-header { display: flex; justify-content: space-between; align-items: center; gap: .5rem; margin-bottom: 1rem; padding-bottom: .75rem; border-bottom: 1px solid var(--border); }
        .card-title { margin: 0; font-size: 1rem; font-weight: 700; }
        .kv-list { display: flex; flex-direction: column; gap: .6rem; font-size: .875rem; }
        .kv-row { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; border-bottom: 1px dashed rgba(30, 41, 59, .8); padding-bottom: .45rem; }
        .kv-row:last-child { border-bottom: 0; padding-bottom: 0; }
        .kv-key { color: var(--muted); shrink: 0; }
        .kv-val { font-weight: 600; text-align: right; word-break: break-word; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: .18rem .55rem;
            border-radius: .4rem;
            font-size: .75rem;
            font-weight: 700;
            letter-spacing: .01em;
        }
        .badge-green { background: rgba(16, 185, 129, .15); color: #34d399; border: 1px solid rgba(16, 185, 129, .3); }
        .badge-blue { background: rgba(59, 130, 246, .15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, .3); }
        .badge-amber { background: rgba(245, 158, 11, .15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, .3); }
        .badge-red { background: rgba(239, 68, 68, .15); color: #f87171; border: 1px solid rgba(239, 68, 68, .3); }
        .badge-slate { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
        .pill-group { display: flex; flex-wrap: wrap; gap: .4rem; justify-content: flex-end; }
        .finding-item {
            padding: .85rem 1rem;
            border-radius: .65rem;
            border: 1px solid var(--border);
            background: var(--surface-alt);
            margin-bottom: .65rem;
        }
        .finding-item:last-child { margin-bottom: 0; }
        .finding-head { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; margin-bottom: .35rem; }
        .finding-title { font-weight: 700; font-size: .9rem; }
        .finding-detail { margin: 0; font-size: .84rem; color: #cbd5e1; }
        .finding-rec { margin: .4rem 0 0; font-size: .8rem; color: #93c5fd; }
        table { width: 100%; border-collapse: collapse; font-size: .82rem; margin-top: .75rem; }
        th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--border); }
        th { color: var(--muted); font-size: .72rem; text-transform: uppercase; }
        details.json-box { background: var(--surface); border: 1px solid var(--border); border-radius: .85rem; padding: 1rem 1.25rem; }
        details.json-box summary { cursor: pointer; font-weight: 700; font-size: .9rem; color: #cbd5e1; }
        pre { background: #020617; padding: 1rem; border-radius: .55rem; overflow-x: auto; font-size: .8rem; color: #e2e8f0; margin-top: .85rem; border: 1px solid var(--border); }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div class="brand">
            <h1>WebInspector PHP <span class="badge badge-blue">v1.0</span></h1>
            <p>Framework-agnostic security, SSL, DNS, SEO, stack &amp; WordPress technical auditor</p>
        </div>
    </header>

    <div class="search-card">
        <form method="get" class="search-form">
            <input type="text" name="url" class="search-input" placeholder="Enter domain or URL (e.g. wordpress.org)" value="<?= $esc($target) ?>" required>
            <button type="submit" class="btn-primary">Run Audit</button>
        </form>
        <div class="presets">
            <span>Quick test:</span>
            <a class="preset-link" href="?url=example.com">example.com</a>
            <a class="preset-link" href="?url=wordpress.org">wordpress.org</a>
            <a class="preset-link" href="?url=github.com">github.com</a>
        </div>
    </div>

    <?php if ($error !== null): ?>
        <div class="alert-error">
            <strong>Inspection Error:</strong> <?= $esc($error) ?>
        </div>
    <?php elseif ($report !== null): ?>
        <?php $summary = $report->getSummary(); ?>
        <?php $findings = $report->getAllFindings(); ?>

        <div class="hero-bar">
            <div>
                <a href="<?= $esc($report->effectiveUrl) ?>" target="_blank" rel="noopener noreferrer" class="hero-url">
                    <?= $esc($report->effectiveUrl) ?>
                </a>
                <div class="hero-meta">
                    <span class="badge <?= $report->statusCode >= 200 && $report->statusCode < 300 ? 'badge-green' : 'badge-amber' ?>">
                        HTTP <?= $esc($report->statusCode) ?>
                    </span>
                    <span class="badge badge-slate"><?= $esc($report->responseTimeMs) ?> ms</span>
                    <?php if ($report->protocolVersion !== null): ?>
                        <span class="badge badge-blue"><?= $esc($report->protocolVersion) ?></span>
                    <?php endif; ?>
                    <span class="badge <?= $gradeColor($report->securityHeaders->grade) ?>">
                        Headers Grade <?= $esc($report->securityHeaders->grade) ?> (<?= $esc($report->securityHeaders->score) ?>/100)
                    </span>
                    <span class="badge badge-blue">
                        CMS: <?= $esc($report->stack->cmsName) ?><?= $report->stack->cmsVersion !== null ? ' v' . $esc($report->stack->cmsVersion) : '' ?>
                    </span>
                </div>
            </div>
            <div class="mono" style="color: var(--muted);">
                Inspected: <?= $esc($report->inspectedAt) ?>
            </div>
        </div>

        <div class="metrics-strip">
            <div class="metric-box">
                <div class="metric-label">SSL Certificate</div>
                <div class="metric-value" style="color: <?= $report->ssl->valid ? '#34d399' : '#f87171' ?>;">
                    <?= $report->ssl->valid ? $esc($report->ssl->daysRemaining) . ' days' : 'Invalid' ?>
                </div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Cookie Score</div>
                <div class="metric-value"><?= $esc($report->cookies->securityScore) ?>%</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">HTML Payload</div>
                <div class="metric-value"><?= $esc($report->domPerformance->htmlSizeKb) ?> KB</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">DOM Assets</div>
                <div class="metric-value"><?= $esc($report->domPerformance->scriptsExternal) ?> JS / <?= $esc($report->domPerformance->stylesCount) ?> CSS</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Findings</div>
                <div class="metric-value"><?= $esc($summary['total']) ?></div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 1.5rem;">
            <div class="card-header">
                <h2 class="card-title">Diagnostic Findings</h2>
                <div class="pill-group">
                    <span class="badge badge-red"><?= $esc($summary['errors']) ?> Errors</span>
                    <span class="badge badge-amber"><?= $esc($summary['warnings']) ?> Warnings</span>
                    <span class="badge badge-blue"><?= $esc($summary['info']) ?> Info</span>
                </div>
            </div>
            <?php if ($findings === []): ?>
                <span class="badge badge-green">No critical issues or warnings detected.</span>
            <?php else: ?>
                <?php foreach ($findings as $finding): ?>
                    <?php
                    $sevBadge = match ($finding->severity) {
                        Severity::Error => 'badge-red',
                        Severity::Warning => 'badge-amber',
                        Severity::Info => 'badge-blue',
                    };
                    ?>
                    <div class="finding-item">
                        <div class="finding-head">
                            <span class="badge <?= $sevBadge ?>"><?= $esc(strtoupper($finding->severity->value)) ?></span>
                            <span class="badge badge-slate mono"><?= $esc($finding->category) ?></span>
                            <span class="finding-title"><?= $esc($finding->title) ?></span>
                        </div>
                        <p class="finding-detail"><?= $esc($finding->detail) ?></p>
                        <?php if ($finding->recommendation !== null): ?>
                            <p class="finding-rec">Recommendation: <?= $esc($finding->recommendation) ?></p>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="grid-2">
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">HTTP Security Headers &amp; Cookies</h2>
                    <span class="badge <?= $gradeColor($report->securityHeaders->grade) ?>">Grade <?= $esc($report->securityHeaders->grade) ?></span>
                </div>
                <div class="kv-list">
                    <?php foreach ($report->securityHeaders->headers as $key => $headerResult): ?>
                        <div class="kv-row">
                            <span class="kv-key mono"><?= $esc($key) ?></span>
                            <span class="kv-val">
                                <?php if ($headerResult->present): ?>
                                    <span class="badge badge-green">Present</span>
                                <?php else: ?>
                                    <span class="badge badge-red">Missing</span>
                                <?php endif; ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                </div>

                <?php if ($report->cookies->totalCount > 0): ?>
                    <table>
                        <thead>
                        <tr>
                            <th>Cookie</th>
                            <th>Secure</th>
                            <th>HttpOnly</th>
                            <th>SameSite</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($report->cookies->cookies as $cookie): ?>
                            <tr>
                                <td class="mono"><?= $esc($cookie->name) ?></td>
                                <td><?= $cookie->secure ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-red">No</span>' ?></td>
                                <td><?= $cookie->httpOnly ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-amber">No</span>' ?></td>
                                <td class="mono"><?= $esc($cookie->sameSite ?? 'Missing') ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">SSL/TLS, DNS &amp; Infrastructure</h2>
                    <span class="badge badge-blue"><?= $esc($report->dns->hostingProvider) ?></span>
                </div>
                <div class="kv-list">
                    <div class="kv-row">
                        <span class="kv-key">IPv4 / PTR</span>
                        <span class="kv-val mono"><?= $esc($report->dns->ipv4 ?? 'N/A') ?><?= $report->dns->reverseDns !== null ? ' (' . $esc($report->dns->reverseDns) . ')' : '' ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Nameservers</span>
                        <span class="kv-val mono"><?= $esc(implode(', ', $report->dns->nameservers) ?: 'None') ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Mail Provider</span>
                        <span class="kv-val"><?= $esc($report->dns->mailProvider) ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Email Auth &amp; CAA</span>
                        <span class="kv-val pill-group">
                            <span class="badge <?= $report->dns->spfConfigured ? 'badge-green' : 'badge-amber' ?>">SPF <?= $report->dns->spfConfigured ? 'OK' : 'Missing' ?></span>
                            <span class="badge <?= $report->dns->dmarcConfigured ? 'badge-green' : 'badge-amber' ?>">DMARC <?= $esc($report->dns->dmarcPolicy ?? ($report->dns->dmarcConfigured ? 'OK' : 'Missing')) ?></span>
                            <span class="badge <?= $report->dns->caaConfigured ? 'badge-green' : 'badge-slate' ?>">CAA <?= $report->dns->caaConfigured ? 'OK' : 'None' ?></span>
                        </span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">SSL Issuer</span>
                        <span class="kv-val"><?= $esc($report->ssl->issuer ?? 'None') ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">SSL Validity</span>
                        <span class="kv-val mono"><?= $report->ssl->enabled ? $esc($report->ssl->validFrom) . ' -> ' . $esc($report->ssl->validTo) : 'HTTP Only' ?></span>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Technology Stack &amp; Privacy</h2>
                    <span class="badge badge-slate mono"><?= $esc($report->stack->webServer) ?></span>
                </div>
                <div class="kv-list">
                    <div class="kv-row">
                        <span class="kv-key">Backend Runtime</span>
                        <span class="kv-val"><?= $esc(implode(', ', $report->stack->backendRuntime)) ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">CDN / WAF</span>
                        <span class="kv-val"><?= $esc(implode(', ', $report->stack->cdnWaf) ?: 'None detected') ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Frontend Libraries</span>
                        <span class="kv-val pill-group">
                            <?php if ($report->stack->frontendLibraries === []): ?>
                                <span style="color: var(--muted);">None detected</span>
                            <?php else: ?>
                                <?php foreach ($report->stack->frontendLibraries as $lib): ?>
                                    <span class="badge <?= $lib['outdated'] ? 'badge-amber' : 'badge-slate' ?>">
                                        <?= $esc($lib['name']) ?><?= $lib['version'] !== null ? ' v' . $esc($lib['version']) : '' ?>
                                    </span>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">CMP Cookie Consent</span>
                        <span class="kv-val"><?= $esc(implode(', ', $report->stack->cmpPrivacy) ?: 'None detected') ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Analytics &amp; Trackers</span>
                        <span class="kv-val">
                            <?php
                            $trackerLabels = array_map(
                                static fn(array $t): string => $t['id'] !== null ? "{$t['name']} ({$t['id']})" : $t['name'],
                                $report->stack->trackingAnalytics,
                            );
echo $esc(implode(', ', $trackerLabels) ?: 'None detected');
?>
                        </span>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">SEO &amp; DOM Performance</h2>
                    <span class="badge badge-slate"><?= $esc(count($report->domPerformance->thirdPartyHosts)) ?> 3rd-party hosts</span>
                </div>
                <div class="kv-list">
                    <div class="kv-row">
                        <span class="kv-key">Title (<?= $esc($report->seo->titleLength) ?> chars)</span>
                        <span class="kv-val"><?= $esc($report->seo->title ?? 'Missing') ?></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">H1 Headings</span>
                        <span class="kv-val"><?= $esc($report->seo->h1Count) ?> (<?= $esc($report->seo->h1Items[0] ?? 'None') ?>)</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Social &amp; Schema.org</span>
                        <span class="kv-val pill-group">
                            <span class="badge <?= $report->seo->openGraph['present'] ? 'badge-green' : 'badge-slate' ?>">OpenGraph</span>
                            <span class="badge <?= $report->seo->twitterCard['present'] ? 'badge-green' : 'badge-slate' ?>">Twitter Card</span>
                            <span class="badge <?= $report->seo->schemaTypes !== [] ? 'badge-blue' : 'badge-slate' ?>">
                                <?= $esc(implode(', ', $report->seo->schemaTypes) ?: 'No JSON-LD') ?>
                            </span>
                        </span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Images Lazy-Loading</span>
                        <span class="kv-val"><?= $esc($report->domPerformance->imagesTotal) ?> total (<?= $esc($report->domPerformance->imagesWithoutLazy) ?> without lazy)</span>
                    </div>
                </div>
            </div>
        </div>

        <?php if ($report->wordpress->isWordPress): ?>
            <div class="card" style="margin-bottom: 1.5rem;">
                <div class="card-header">
                    <h2 class="card-title">WordPress Deep Diagnostics</h2>
                    <span class="badge badge-green">Core <?= $esc($report->wordpress->version ?? 'Version Hidden') ?></span>
                </div>
                <div class="kv-list">
                    <div class="kv-row">
                        <span class="kv-key">Active Theme</span>
                        <span class="kv-val">
                            <?= $esc($report->wordpress->theme['name']) ?>
                            <?= $report->wordpress->theme['version'] !== null ? ' v' . $esc($report->wordpress->theme['version']) : '' ?>
                            <?= $report->wordpress->theme['is_child'] ? ' (Child of ' . $esc($report->wordpress->theme['parent_theme']) . ')' : '' ?>
                        </span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Hardening Probes</span>
                        <span class="kv-val pill-group">
                            <span class="badge <?= !empty($report->wordpress->hardening['rest_users_exposed']) ? 'badge-amber' : 'badge-green' ?>">
                                REST Users: <?= !empty($report->wordpress->hardening['rest_users_exposed']) ? 'Exposed' : 'Protected' ?>
                            </span>
                            <span class="badge <?= !empty($report->wordpress->hardening['author_enum_exposed']) ? 'badge-amber' : 'badge-green' ?>">
                                ?author=1: <?= !empty($report->wordpress->hardening['author_enum_exposed']) ? 'Exposed' : 'Protected' ?>
                            </span>
                            <span class="badge <?= !empty($report->wordpress->hardening['xmlrpc_active']) ? 'badge-amber' : 'badge-green' ?>">
                                XML-RPC: <?= !empty($report->wordpress->hardening['xmlrpc_active']) ? 'Active' : 'Disabled' ?>
                            </span>
                            <span class="badge <?= !empty($report->wordpress->hardening['debug_log_exposed']) ? 'badge-red' : 'badge-green' ?>">
                                debug.log: <?= !empty($report->wordpress->hardening['debug_log_exposed']) ? 'Exposed' : 'Protected' ?>
                            </span>
                        </span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">Detected Plugins (<?= $esc(count($report->wordpress->plugins)) ?>)</span>
                        <span class="kv-val pill-group">
                            <?php if ($report->wordpress->plugins === []): ?>
                                <span style="color: var(--muted);">None detected publicly</span>
                            <?php else: ?>
                                <?php foreach ($report->wordpress->plugins as $plugin): ?>
                                    <span class="badge badge-slate">
                                        <?= $esc($plugin['name']) ?><?= $plugin['version'] !== null ? ' v' . $esc($plugin['version']) : '' ?>
                                    </span>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </span>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <details class="json-box">
            <summary>View Raw JSON Report Payload</summary>
            <pre><?= $esc($reportJson) ?></pre>
        </details>
    <?php endif; ?>
</div>
</body>
</html>
<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use LeandroPerez\WebInspector\Ai\GeminiSummarizer;
use LeandroPerez\WebInspector\Dto\AuditReport;
use LeandroPerez\WebInspector\Dto\Severity;
use LeandroPerez\WebInspector\WebInspector;

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$readConfigVar = static function (string $key, string $default = ''): string {
    $runtimeVal = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
    if (is_string($runtimeVal) && trim($runtimeVal) !== '') {
        return trim($runtimeVal);
    }

    $envFiles = [
        dirname(__DIR__) . '/.env.local',
        dirname(__DIR__) . '/.env',
    ];

    foreach ($envFiles as $envFile) {
        if (!is_file($envFile)) {
            continue;
        }
        $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }
            if (str_starts_with($trimmed, $key . '=')) {
                $raw = trim(substr($trimmed, strlen($key . '=')));
                $unquoted = trim($raw, " \t\n\r\0\x0B\"'");
                if ($unquoted !== '') {
                    return $unquoted;
                }
            }
        }
    }

    return $default;
};

// Handle asynchronous AI Summary POST request
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['action'] ?? '') === 'ai_summary') {
    header('Content-Type: application/json; charset=utf-8');

    $apiKey = $readConfigVar('GEMINI_API_KEY');
    if ($apiKey === '') {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'GEMINI_API_KEY non configurata. Imposta la variabile d\'ambiente GEMINI_API_KEY oppure crea un file .env nella root del progetto con GEMINI_API_KEY=la_tua_chiave.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $targetUrl = trim((string) ($_POST['target'] ?? ''));
    $language = in_array($_POST['lang'] ?? 'it', ['it', 'en'], true) ? (string) $_POST['lang'] : 'it';

    if ($targetUrl === '') {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Target URL mancante per la generazione dell\'analisi AI.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    try {
        $reportObj = null;
        $cachedReports = is_array($_SESSION['wi_reports'] ?? null) ? $_SESSION['wi_reports'] : [];
        if (isset($cachedReports[$targetUrl]) && is_string($cachedReports[$targetUrl])) {
            $unserialized = @unserialize($cachedReports[$targetUrl], ['allowed_classes' => true]);
            if ($unserialized instanceof AuditReport) {
                $reportObj = $unserialized;
            }
        }

        if (!$reportObj instanceof AuditReport) {
            $reportObj = (new WebInspector())->inspect($targetUrl);
        }

        $model = $readConfigVar('GEMINI_MODEL', 'gemini-2.5-flash');
        $summarizer = new GeminiSummarizer(apiKey: $apiKey, model: $model);
        $summaryMarkdown = $summarizer->summarize($reportObj, $language);

        echo json_encode([
            'success' => true,
            'model' => $model,
            'summary' => $summaryMarkdown,
        ], JSON_UNESCAPED_UNICODE);
    } catch (\Throwable $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Errore durante l\'analisi AI: ' . $e->getMessage(),
        ], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

$target = trim((string) ($_GET['url'] ?? ''));
$report = null;
$reportJson = null;
$error = null;
$hasGeminiKey = $readConfigVar('GEMINI_API_KEY') !== '';

if ($target !== '') {
    try {
        $inspector = new WebInspector();
        $report = $inspector->inspect($target);
        $reportJson = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        $_SESSION['wi_reports'] = is_array($_SESSION['wi_reports'] ?? null) ? $_SESSION['wi_reports'] : [];
        $_SESSION['wi_reports'][$report->effectiveUrl] = serialize($report);
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
            --ai-accent: #6366f1;
            --ai-hover: #4f46e5;
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
            display: inline-flex;
            align-items: center;
            gap: .5rem;
        }
        .btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
        .btn-primary:disabled { opacity: .6; cursor: not-allowed; }
        .btn-ai {
            padding: .55rem 1rem;
            border-radius: .5rem;
            border: 1px solid rgba(99, 102, 241, .45);
            background: var(--ai-accent);
            color: #fff;
            font-weight: 600;
            font-size: .85rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: .45rem;
        }
        .btn-ai:hover:not(:disabled) { background: var(--ai-hover); }
        .btn-ai:disabled { opacity: .6; cursor: not-allowed; }
        .select-lang {
            padding: .5rem .65rem;
            border-radius: .5rem;
            border: 1px solid #334155;
            background: var(--surface-alt);
            color: var(--text);
            font-size: .82rem;
            font-weight: 600;
        }
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
            font-size: .9rem;
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
        .hero-actions { display: flex; flex-wrap: wrap; align-items: center; gap: .6rem; }
        .hero-url { font-size: 1.15rem; font-weight: 700; color: #fff; word-break: break-all; text-decoration: none; }
        .hero-url:hover { color: #60a5fa; }
        .hero-meta { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .45rem; }
        .ai-card {
            background: linear-gradient(180deg, rgba(30, 27, 75, .45) 0%, var(--surface) 100%);
            border: 1px solid rgba(99, 102, 241, .4);
            border-radius: .85rem;
            padding: 1.25rem 1.4rem;
            margin-bottom: 1.5rem;
            display: none;
        }
        .ai-card.visible { display: block; }
        .ai-loader {
            display: none;
            align-items: center;
            gap: .75rem;
            padding: .75rem 0;
            color: #c7d2fe;
            font-size: .9rem;
            font-weight: 500;
        }
        .ai-loader.visible { display: flex; }
        .ai-output { font-size: .9rem; color: #e2e8f0; line-height: 1.65; }
        .ai-output h3, .ai-output h4 { color: #a5b4fc; margin: 1rem 0 .4rem; }
        .ai-output h3:first-child, .ai-output h4:first-child { margin-top: 0; }
        .ai-output ul { margin: .35rem 0 .75rem; padding-left: 1.25rem; }
        .ai-output li { margin-bottom: .3rem; }
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
        .kv-key { color: var(--muted); flex-shrink: 0; }
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

        /* Preloader Overlay & Spinners */
        .preloader-overlay {
            position: fixed;
            inset: 0;
            background: rgba(11, 17, 32, .84);
            backdrop-filter: blur(4px);
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1rem;
            z-index: 9999;
            padding: 1.5rem;
            text-align: center;
        }
        .preloader-overlay.visible { display: flex; }
        .spinner {
            width: 44px;
            height: 44px;
            border: 3.5px solid rgba(59, 130, 246, .25);
            border-top-color: #3b82f6;
            border-radius: 50%;
            animation: spin .8s linear infinite;
        }
        .spinner-sm {
            width: 18px;
            height: 18px;
            border: 2.5px solid rgba(165, 180, 252, .3);
            border-top-color: #a5b4fc;
            border-radius: 50%;
            animation: spin .8s linear infinite;
            flex-shrink: 0;
        }
        .preloader-title { font-size: 1.05rem; font-weight: 700; color: #fff; margin: 0; }
        .preloader-sub { font-size: .85rem; color: var(--muted); margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>

<div id="globalPreloader" class="preloader-overlay" role="status" aria-live="polite">
    <div class="spinner"></div>
    <p class="preloader-title">Running Technical Website Audit...</p>
    <p id="preloaderTargetText" class="preloader-sub">Resolving DNS, SSL/TLS, HTTP headers &amp; stack</p>
</div>

<div class="container">
    <header>
        <div class="brand">
            <h1>WebInspector PHP <span class="badge badge-blue">v1.0</span></h1>
            <p>Framework-agnostic security, SSL, DNS, SEO, stack &amp; WordPress technical auditor</p>
        </div>
        <div>
            <span class="badge <?= $hasGeminiKey ? 'badge-green' : 'badge-amber' ?>">
                GEMINI_API_KEY: <?= $hasGeminiKey ? 'Configured' : 'Not Set' ?>
            </span>
        </div>
    </header>

    <div class="search-card">
        <form id="inspectForm" method="get" class="search-form">
            <input type="text" id="urlInput" name="url" class="search-input" placeholder="Enter domain or URL (e.g. wordpress.org)" value="<?= $esc($target) ?>" required>
            <button type="submit" id="inspectBtn" class="btn-primary">Run Audit</button>
        </form>
        <div class="presets">
            <span>Quick test:</span>
            <a class="preset-link" href="?url=example.com" data-preset="example.com">example.com</a>
            <a class="preset-link" href="?url=wordpress.org" data-preset="wordpress.org">wordpress.org</a>
            <a class="preset-link" href="?url=github.com" data-preset="github.com">github.com</a>
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
            <div class="hero-actions">
                <select id="aiLangSelect" class="select-lang" aria-label="AI Summary Language">
                    <option value="it" selected>IT</option>
                    <option value="en">EN</option>
                </select>
                <button type="button" id="aiSummaryBtn" class="btn-ai" data-target="<?= $esc($report->effectiveUrl) ?>">
                    Generate AI Summary
                </button>
            </div>
        </div>

        <div id="aiSummaryCard" class="ai-card">
            <div class="card-header">
                <h2 class="card-title">AI Diagnostic Summary (Google Gemini)</h2>
                <span id="aiModelBadge" class="badge badge-blue">Gemini</span>
            </div>
            <div id="aiLoader" class="ai-loader">
                <div class="spinner-sm"></div>
                <span>Generating operational diagnosis with Google Gemini...</span>
            </div>
            <div id="aiErrorBox" class="alert-error" style="display: none; margin-bottom: 0;"></div>
            <div id="aiOutput" class="ai-output"></div>
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

<script>
(() => {
    const preloader = document.getElementById('globalPreloader');
    const preloaderSub = document.getElementById('preloaderTargetText');
    const inspectForm = document.getElementById('inspectForm');
    const urlInput = document.getElementById('urlInput');
    const inspectBtn = document.getElementById('inspectBtn');

    const showInspectionPreloader = (targetLabel) => {
        if (preloaderSub && targetLabel) {
            preloaderSub.textContent = `Scanning ${targetLabel} — DNS, SSL/TLS, Headers & Stack...`;
        }
        if (preloader) {
            preloader.classList.add('visible');
        }
        if (inspectBtn) {
            inspectBtn.disabled = true;
            inspectBtn.textContent = 'Scanning...';
        }
    };

    window.addEventListener('pageshow', () => {
        if (preloader) {
            preloader.classList.remove('visible');
        }
        if (inspectBtn) {
            inspectBtn.disabled = false;
            inspectBtn.textContent = 'Run Audit';
        }
    });

    if (inspectForm) {
        inspectForm.addEventListener('submit', () => {
            const val = (urlInput?.value || '').trim();
            if (val !== '') {
                showInspectionPreloader(val);
            }
        });
    }

    document.querySelectorAll('.preset-link').forEach((link) => {
        link.addEventListener('click', () => {
            const domain = link.getAttribute('data-preset') || link.textContent.trim();
            if (urlInput) {
                urlInput.value = domain;
            }
            showInspectionPreloader(domain);
        });
    });

    const aiBtn = document.getElementById('aiSummaryBtn');
    const aiLangSelect = document.getElementById('aiLangSelect');
    const aiCard = document.getElementById('aiSummaryCard');
    const aiLoader = document.getElementById('aiLoader');
    const aiErrorBox = document.getElementById('aiErrorBox');
    const aiOutput = document.getElementById('aiOutput');
    const aiModelBadge = document.getElementById('aiModelBadge');

    const escapeHtml = (str) => {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    };

    const renderMarkdown = (text) => {
        let html = escapeHtml(text || '');
        html = html.replace(/^### (.*)$/gm, '<h4>$1</h4>');
        html = html.replace(/^## (.*)$/gm, '<h3>$1</h3>');
        html = html.replace(/^# (.*)$/gm, '<h3>$1</h3>');
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/^\s*[-*]\s+(.*)$/gm, '<li>$1</li>');
        html = html.replace(/((?:<li>.*<\/li>\s*)+)/gs, '<ul>$1</ul>');
        html = html.replace(/\n{2,}/g, '<br><br>');
        html = html.replace(/\n/g, '<br>');
        return html;
    };

    if (aiBtn) {
        aiBtn.addEventListener('click', async () => {
            const target = aiBtn.getAttribute('data-target') || '';
            const lang = aiLangSelect ? aiLangSelect.value : 'it';

            if (aiCard) aiCard.classList.add('visible');
            if (aiLoader) aiLoader.classList.add('visible');
            if (aiErrorBox) {
                aiErrorBox.style.display = 'none';
                aiErrorBox.textContent = '';
            }
            if (aiOutput) aiOutput.innerHTML = '';

            aiBtn.disabled = true;
            const originalLabel = aiBtn.textContent;
            aiBtn.textContent = 'Analyzing...';

            try {
                const body = new URLSearchParams({
                    action: 'ai_summary',
                    target,
                    lang,
                });

                const response = await fetch(window.location.pathname, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                        'Accept': 'application/json',
                    },
                    body: body.toString(),
                });

                const data = await response.json();

                if (!response.ok || !data.success) {
                    if (aiErrorBox) {
                        aiErrorBox.textContent = data.error || `HTTP ${response.status} error during AI analysis.`;
                        aiErrorBox.style.display = 'block';
                    }
                    return;
                }

                if (aiModelBadge && data.model) {
                    aiModelBadge.textContent = data.model;
                }
                if (aiOutput) {
                    aiOutput.innerHTML = renderMarkdown(data.summary || '');
                }
            } catch (err) {
                if (aiErrorBox) {
                    aiErrorBox.textContent = err?.message || 'Communication error during AI summary generation.';
                    aiErrorBox.style.display = 'block';
                }
            } finally {
                if (aiLoader) aiLoader.classList.remove('visible');
                aiBtn.disabled = false;
                aiBtn.textContent = originalLabel;
            }
        });
    }
})();
</script>
</body>
</html>
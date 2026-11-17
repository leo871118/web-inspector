<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use LeandroPerez\WebInspector\WebInspector;

$target = trim((string) ($_GET['url'] ?? ''));
$reportJson = null;
$error = null;

if ($target !== '') {
    try {
        $inspector = new WebInspector();
        $report = $inspector->inspect($target);
        $reportJson = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } catch (\Throwable $e) {
        $error = $e->getMessage();
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>WebInspector PHP — Demo</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #e2e8f0; }
        form { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
        input { flex: 1; padding: .65rem .9rem; border-radius: .5rem; border: 1px solid #334155; background: #1e293b; color: #fff; }
        button { padding: .65rem 1.2rem; border-radius: .5rem; border: 0; background: #3b82f6; color: #fff; font-weight: 600; cursor: pointer; }
        pre { background: #1e293b; padding: 1rem; border-radius: .5rem; overflow-x: auto; font-size: .85rem; }
        .err { background: #7f1d1d; padding: .8rem 1rem; border-radius: .5rem; }
    </style>
</head>
<body>
    <h1>WebInspector PHP</h1>
    <form method="get">
        <input type="text" name="url" placeholder="example.com" value="<?= htmlspecialchars($target, ENT_QUOTES) ?>" required>
        <button type="submit">Inspect</button>
    </form>
    <?php if ($error !== null): ?>
        <div class="err"><?= htmlspecialchars($error, ENT_QUOTES) ?></div>
    <?php elseif ($reportJson !== null): ?>
        <pre><?= htmlspecialchars($reportJson, ENT_QUOTES) ?></pre>
    <?php endif; ?>
</body>
</html>
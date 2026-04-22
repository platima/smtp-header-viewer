<?php
// -----------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------
define('PYTHON_BIN',      'python3');
define('SCRIPT_PATH',     __DIR__ . '/decode-spam-headers.py');
define('MAX_INPUT_BYTES', 512 * 1024); // 512 KB sanity cap for file uploads
define('MAX_PASTE_CHARS', 50000);       // max characters for pasted headers
define('APP_VERSION',     '1.18');
define('DEBUG_MODE',      getenv('DSH_DEBUG') === '1');
define('RATE_LIMIT',      10);          // max requests per window
define('RATE_WINDOW',     60);          // seconds

// -----------------------------------------------------------------------
// Security headers (sent before any output)
// -----------------------------------------------------------------------
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; frame-src 'self' blob:; img-src 'self' data:; connect-src 'self'");

// -----------------------------------------------------------------------
// Session & CSRF
// -----------------------------------------------------------------------
session_start();

function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(): bool {
    $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    return hash_equals(csrf_token(), $token);
}

// -----------------------------------------------------------------------
// Rate limiting (file-based, per-IP)
// -----------------------------------------------------------------------
function check_rate_limit(): bool {
    $dir = sys_get_temp_dir() . '/dsh_rate';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $ip   = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $file = $dir . '/' . md5($ip) . '.json';
    $now  = time();

    $data = ['timestamps' => []];
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        if ($raw !== false) {
            $data = json_decode($raw, true) ?: ['timestamps' => []];
        }
    }

    // Prune entries outside the window
    $data['timestamps'] = array_values(array_filter(
        $data['timestamps'],
        fn($t) => ($now - $t) < RATE_WINDOW
    ));

    if (count($data['timestamps']) >= RATE_LIMIT) {
        return false;
    }

    $data['timestamps'][] = $now;
    @file_put_contents($file, json_encode($data), LOCK_EX);
    return true;
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
function is_msg_file(string $name): bool {
    return strtolower(pathinfo($name, PATHINFO_EXTENSION)) === 'msg';
}

/** Allowed upload extensions for server-side validation. */
function is_allowed_upload(string $name): bool {
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    return in_array($ext, ['eml', 'msg', 'txt'], true);
}

// -----------------------------------------------------------------------
// AJAX: extract internet headers from a .msg binary upload.
// The RFC 822 header block is stored as plain text inside the OLE2
// container. We scan for the largest contiguous block of header-like
// lines rather than parsing the full OLE2 format.
// Called via fetch() from JS with action=extract_msg_headers.
// -----------------------------------------------------------------------
if (isset($_GET['action']) && $_GET['action'] === 'extract_msg_headers') {
    header('Content-Type: application/json');
    $result = ['ok' => false, 'headers' => '', 'error' => ''];

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $result['error'] = 'Invalid request method.';
        echo json_encode($result);
        exit;
    }

    if (!verify_csrf()) {
        $result['error'] = 'Invalid or expired session. Please reload the page.';
        echo json_encode($result);
        exit;
    }

    if (!check_rate_limit()) {
        http_response_code(429);
        $result['error'] = 'Too many requests. Please wait a moment.';
        echo json_encode($result);
        exit;
    }

    if (empty($_FILES['msgfile']['tmp_name']) || $_FILES['msgfile']['error'] !== UPLOAD_ERR_OK) {
        $result['error'] = 'No file received.';
        echo json_encode($result);
        exit;
    }

    if (!is_allowed_upload($_FILES['msgfile']['name'] ?? '')) {
        $result['error'] = 'Only .eml, .msg and .txt files are accepted.';
        echo json_encode($result);
        exit;
    }

    $raw = file_get_contents($_FILES['msgfile']['tmp_name']);
    if ($raw === false) {
        $result['error'] = 'Could not read file.';
        echo json_encode($result);
        exit;
    }

    // The transport headers are stored as a plain-text stream inside the
    // OLE2 compound file. Extract them by searching for the largest block
    // that looks like RFC 822 headers (lines matching "Header-Name: value"
    // or folded continuation lines, terminated by a double CRLF/LF).
    $headers = '';
    $best    = '';

    // Normalise line endings and split the binary into printable chunks
    $text = preg_replace('/\r\n/', "\n", $raw);
    $text = preg_replace('/[^\x09\x0a\x20-\x7e]/', "\n", $text);

    // Split into candidate blocks separated by blank lines
    $blocks = preg_split('/\n{2,}/', $text);
    foreach ($blocks as $block) {
        $lines = explode("\n", trim($block));
        $score = 0;
        $valid = [];
        foreach ($lines as $line) {
            if (preg_match('/^[A-Za-z][\w\-]{1,60}:/', $line)) {
                $score += 2;
                $valid[] = $line;
            } elseif (preg_match('/^\s+\S/', $line) && $valid) {
                // Folded continuation
                $score += 1;
                $valid[] = $line;
            } else {
                break; // stop at first non-header line
            }
        }
        if ($score > 4 && count($valid) > strlen($best) / 60) {
            $candidate = implode("\n", $valid);
            if (strlen($candidate) > strlen($best)) {
                $best = $candidate;
            }
        }
    }

    if ($best !== '') {
        $result['ok']      = true;
        $result['headers'] = $best;
    } else {
        $result['error'] = 'Could not locate a header block in this .msg file. '
                         . 'Try opening in Outlook and copying the internet headers manually.';
    }

    echo json_encode($result);
    exit;
}

// -----------------------------------------------------------------------
// Processing
// -----------------------------------------------------------------------
$result_html   = '';
$script_errors = [];
$processing    = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $processing  = true;
    $raw_headers = '';

    if (!verify_csrf()) {
        $script_errors[] = 'Invalid or expired session. Please reload the page and try again.';
    } elseif (!check_rate_limit()) {
        http_response_code(429);
        $script_errors[] = 'Too many requests. Please wait a moment before submitting again.';
    } else {
        if (!empty($_FILES['emlfile']['tmp_name']) && $_FILES['emlfile']['error'] === UPLOAD_ERR_OK) {
            if (!is_allowed_upload($_FILES['emlfile']['name'] ?? '')) {
                $script_errors[] = 'Only .eml, .msg and .txt files are accepted.';
            } else {
                $raw_headers = file_get_contents($_FILES['emlfile']['tmp_name']);
            }
        } elseif (!empty($_POST['headers'])) {
            $raw_headers = $_POST['headers'];
        }

        $raw_headers = trim($raw_headers ?? '');

        if (empty($script_errors) && empty($raw_headers)) {
            $script_errors[] = 'No headers provided. Paste headers into the text box or upload an .eml / .msg file.';
        } elseif (empty($script_errors) && isset($_POST['headers']) && strlen($raw_headers) > MAX_PASTE_CHARS) {
            $script_errors[] = 'Pasted headers exceed the ' . number_format(MAX_PASTE_CHARS) . '-character limit. '
                . 'If you have a full .eml file, upload or drop it — the body is stripped automatically.';
        } elseif (empty($script_errors) && strlen($raw_headers) > MAX_INPUT_BYTES) {
            $script_errors[] = 'Input exceeds the 512 KB limit.';
        } elseif (empty($script_errors)) {
            $tmp = tempnam(sys_get_temp_dir(), 'dsh_');
            register_shutdown_function(function () use ($tmp) { @unlink($tmp); });
            file_put_contents($tmp, $raw_headers);

            $resolve_flag = !empty($_POST['resolve']) ? '-r' : '-R';
            $env = 'DECODE_SPAM_HEADERS_WEB=1';
            $cmd = $env . ' '
                 . PYTHON_BIN
                 . ' ' . escapeshellarg(SCRIPT_PATH)
                 . ' -f html'
                 . ' ' . $resolve_flag
                 . ' ' . escapeshellarg($tmp)
                 . ' 2>&1';

            $output = shell_exec($cmd);
            @unlink($tmp);

            if ($output === null || $output === false) {
                $script_errors[] = 'Failed to execute the analysis script. Check that python3 is in PATH and the script is readable by the web server user.';
            } else {
                $lines      = explode("\n", $output);
                $html_lines = [];
                $raw_output = $output;

                foreach ($lines as $line) {
                    if (preg_match('/^\s*\[!\]/', $line)) {
                        if (preg_match('/pip3 install (\S+)/', $line, $m)) {
                            $pkg = htmlspecialchars($m[1]);
                            $script_errors[] = 'Missing Python dependency: <code>' . $pkg . '</code> &mdash; '
                                . 'install it on the server: <code>pip3 install ' . $pkg . ' --break-system-packages</code>';
                        } else {
                            $script_errors[] = htmlspecialchars(trim($line));
                        }
                    } else {
                        $html_lines[] = $line;
                    }
                }

                $candidate = implode("\n", $html_lines);

                if (strpos($candidate, '<html') !== false || strpos($candidate, '<body') !== false) {
                    $result_html = $candidate;
                } elseif (empty($script_errors)) {
                    $script_errors[] = 'Script returned no recognisable output. '
                        . 'Make sure you are uploading a plain-text .eml file &mdash; .msg binary files should be dropped onto the <strong>textarea</strong> below the dropzone to extract headers first.';
                    if (DEBUG_MODE) {
                        $script_errors[] = '<strong>Debug output:</strong><pre style="white-space:pre-wrap;word-break:break-all;margin-top:8px;">'
                            . htmlspecialchars($raw_output) . '</pre>';
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SMTP Header Analyser</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Intel+One+Mono:wght@400;600;700&family=Source+Sans+3:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  /* Solarised Dark (default) */
  :root {
    --base03:  #002b36;
    --base02:  #073642;
    --base01:  #586e75;
    --base00:  #657b83;
    --base0:   #839496;
    --base1:   #93a1a1;
    --base2:   #eee8d5;
    --base3:   #fdf6e3;
    --yellow:  #b58900;
    --orange:  #cb4b16;
    --red:     #dc322f;
    --magenta: #d33682;
    --violet:  #6c71c4;
    --blue:    #268bd2;
    --cyan:    #2aa198;
    --green:   #859900;
    --bg:      var(--base03);
    --surface: var(--base02);
    --border:  #0a4a5a;
    --accent:  var(--cyan);
    --accent2: var(--violet);
    --text:    var(--base0);
    --heading: var(--base1);
    --muted:   var(--base01);
    --radius:  10px;
    --mono:    'Intel One Mono', monospace;
    --sans:    'Source Sans 3', sans-serif;
    color-scheme: dark;
  }

  /* Solarised Light */
  :root[data-theme="light"] {
    --bg:      var(--base3);
    --surface: var(--base2);
    --border:  #d3cbb7;
    --text:    var(--base00);
    --heading: var(--base01);
    --muted:   var(--base1);
    color-scheme: light;
  }

  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
      --bg:      var(--base3);
      --surface: var(--base2);
      --border:  #d3cbb7;
      --text:    var(--base00);
      --heading: var(--base01);
      --muted:   var(--base1);
      color-scheme: light;
    }
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(var(--border) 1px, transparent 1px),
      linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 40px 40px;
    opacity: 0.35;
    pointer-events: none;
    z-index: 0;
  }

  .wrapper {
    position: relative;
    z-index: 1;
    width: 100%;
    max-width: min(80vw, 1400px);
    padding: 40px 24px 60px;
  }

  header { margin-bottom: 36px; }

  h1 {
    font-family: var(--sans);
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.01em;
    color: var(--heading);
  }

  h1 span { color: var(--accent); }

  .tagline {
    margin-top: 6px;
    font-size: 0.75rem;
    color: var(--muted);
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px;
    margin-bottom: 20px;
  }

  .card-title {
    font-family: var(--sans);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 14px;
  }

  /* Drop zone */
  #dropzone {
    border: 2px dashed var(--border);
    border-radius: var(--radius);
    padding: 24px;
    text-align: center;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
    margin-bottom: 18px;
    position: relative;
  }

  #dropzone:hover,
  #dropzone.dragover {
    border-color: var(--accent);
    background: rgba(74, 240, 176, 0.04);
  }

  #dropzone .dz-icon { font-size: 1.8rem; margin-bottom: 6px; display: block; color: var(--accent); }
  #dropzone p        { font-size: 0.8rem; color: var(--muted); line-height: 1.6; }
  #dropzone p strong { color: var(--text); }

  #dropzone .dz-sub  {
    margin-top: 6px;
    font-size: 0.7rem;
    color: var(--muted);
    opacity: 0.7;
  }

  #file-input {
    position: absolute;
    inset: 0;
    opacity: 0;
    cursor: pointer;
    width: 100%;
    height: 100%;
  }

  #file-name { margin-top: 8px; font-size: 0.75rem; color: var(--accent); min-height: 1em; }

  .divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 18px 0;
    color: var(--muted);
    font-size: 0.7rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .divider::before,
  .divider::after { content: ''; flex: 1; height: 1px; background: var(--border); }

  /* Textarea with drop-extract support */
  .textarea-wrap { position: relative; }

  .textarea-wrap.dragover textarea {
    border-color: var(--accent2);
    background: rgba(123, 108, 255, 0.06);
  }

  .textarea-drop-hint {
    display: none;
    position: absolute;
    inset: 0;
    background: rgba(0, 43, 54, 0.85);
    border-radius: var(--radius);
    align-items: center;
    justify-content: center;
    font-family: var(--sans);
    font-weight: 700;
    font-size: 0.85rem;
    color: var(--accent2);
    letter-spacing: 0.04em;
    pointer-events: none;
    border: 2px dashed var(--accent2);
  }

  .textarea-wrap.dragover .textarea-drop-hint { display: flex; }

  textarea {
    width: 100%;
    min-height: 180px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.78rem;
    line-height: 1.6;
    padding: 14px;
    resize: vertical;
    transition: border-color 0.2s, background 0.2s;
    outline: none;
    display: block;
  }

  textarea:focus  { border-color: var(--accent2); }
  textarea::placeholder { color: var(--muted); }

  .options {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 16px;
  }

  .toggle-label {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: 0.8rem;
    color: var(--muted);
    user-select: none;
    transition: color 0.2s;
  }

  .toggle-label:hover { color: var(--text); }

  .toggle-label input[type=checkbox] {
    appearance: none;
    width: 32px;
    height: 18px;
    background: var(--border);
    border-radius: 9px;
    position: relative;
    cursor: pointer;
    transition: background 0.2s;
  }

  .toggle-label input[type=checkbox]:checked { background: var(--accent2); }

  .toggle-label input[type=checkbox]::after {
    content: '';
    position: absolute;
    top: 3px; left: 3px;
    width: 12px; height: 12px;
    border-radius: 50%;
    background: #fff;
    transition: transform 0.2s;
  }

  .toggle-label input[type=checkbox]:checked::after { transform: translateX(14px); }

  .hint { font-size: 0.68rem; color: var(--muted); margin-left: 4px; }

  .actions { display: flex; justify-content: flex-end; margin-top: 20px; }

  button[type=submit] {
    background: var(--accent);
    color: var(--bg);
    border: none;
    border-radius: var(--radius);
    font-family: var(--sans);
    font-weight: 700;
    font-size: 0.9rem;
    letter-spacing: 0.04em;
    padding: 12px 32px;
    cursor: pointer;
    transition: opacity 0.2s, transform 0.1s;
  }

  button[type=submit]:hover    { opacity: 0.88; transform: translateY(-1px); }
  button[type=submit]:active   { transform: translateY(0); }
  button[type=submit]:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  /* Error boxes */
  .error-box {
    background: rgba(255, 95, 109, 0.08);
    border: 1px solid var(--red);
    border-radius: var(--radius);
    padding: 14px 18px;
    color: var(--red);
    font-size: 0.82rem;
    margin-bottom: 12px;
  }

  .error-box code {
    background: rgba(255,255,255,0.08);
    padding: 1px 5px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 0.78rem;
    color: #ffb3b8;
  }

  /* Result iframe - explicit white bg prevents browser dark-mode forcing */
  #result-container {
    width: 100%;
    border-radius: var(--radius);
    overflow: hidden;
    border: 1px solid var(--border);
    animation: fadeIn 0.4s ease;
    margin-bottom: 16px;
  }

  #result-frame {
    width: 100%;
    border: none;
    display: block;
    min-height: 600px;
    background: #ffffff;
    color-scheme: light;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .back-link { text-align: right; font-size: 0.78rem; }
  .back-link a { color: var(--accent2); text-decoration: none; }
  .back-link a:hover { text-decoration: underline; }

  footer {
    margin-top: 40px;
    font-size: 0.68rem;
    color: var(--muted);
    text-align: center;
    letter-spacing: 0.06em;
  }

  footer a { color: var(--accent2); text-decoration: none; }
  footer a:hover { text-decoration: underline; }

  .resources-bar {
    margin-top: 36px;
    padding: 10px 0;
    border-top: 1px solid var(--border);
    font-size: 0.72rem;
    color: var(--muted);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .resources-bar a { color: var(--accent2); text-decoration: none; }
  .resources-bar a:hover { text-decoration: underline; }
  .resources-sep { color: var(--border); }

  @keyframes ellipsis {
    0%   { content: '.';   }
    33%  { content: '..';  }
    66%  { content: '...'; }
  }

  .anim-ellipsis::after {
    content: '.';
    animation: ellipsis 1.2s steps(1, end) infinite;
    display: inline-block;
    width: 1.4ch;
    text-align: left;
  }

  /* Theme toggle */
  .theme-toggle {
    background: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--muted);
    cursor: pointer;
    font-family: var(--sans);
    font-size: 0.75rem;
    padding: 4px 10px;
    transition: color 0.2s, border-color 0.2s;
  }
  .theme-toggle:hover { color: var(--text); border-color: var(--accent); }

  .char-counter {
    text-align: right;
    font-size: 0.7rem;
    color: var(--muted);
    margin-top: 4px;
    transition: color 0.2s;
  }
  .char-counter.warn  { color: var(--yellow); }
  .char-counter.limit { color: var(--red); }

  header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }
</style>
</head>
<body>
<div class="wrapper">

  <header>
    <div>
      <h1><a href="<?= htmlspecialchars(strtok($_SERVER['REQUEST_URI'], '?')) ?>" style="text-decoration:none;color:inherit;">SMTP Header <span>Analyser</span></a></h1>
      <p class="tagline">Powered by decode-spam-headers.py &mdash; @mariuszbit</p>
    </div>
    <button class="theme-toggle" id="theme-toggle" title="Toggle light/dark mode">&#9788; Light</button>
  </header>

  <?php foreach ($script_errors as $err): ?>
    <div class="error-box">&#9888; <?= $err ?></div>
  <?php endforeach; ?>

  <?php if (!$processing || (!$result_html && !empty($script_errors))): ?>
  <form method="POST" enctype="multipart/form-data" id="analyser-form"
    action="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
    <div class="card">
      <div class="card-title">Input</div>

      <div id="dropzone">
        <input type="file" name="emlfile" id="file-input" accept=".eml,.msg,.txt,message/rfc822">
        <span class="dz-icon">&#128274;</span>
        <p><strong>Drop an .eml or .msg file here to analyse immediately</strong><br>or click to browse</p>
        <p class="dz-sub">.eml body is stripped automatically &nbsp;|&nbsp; .msg headers are extracted first, then submitted</p>
      </div>
      <div id="file-name"></div>

      <div class="divider">or paste / drop headers below</div>

      <div class="textarea-wrap" id="textarea-wrap">
        <textarea name="headers" id="headers-input" maxlength="50000"
          placeholder="Received: from mail-wr1-f99.google.com ...&#10;X-Forefront-Antispam-Report: CIP:209.85.222.99; ...&#10;&#10;Paste raw email headers here, or drop a file above."
        ><?= htmlspecialchars($_POST['headers'] ?? '') ?></textarea>
        <div class="char-counter" id="char-counter"><span id="char-count">0</span>&nbsp;/&nbsp;50,000</div>
        <div class="textarea-drop-hint">&#8595; Drop .eml or .msg to extract headers</div>
      </div>

      <div class="options">
        <label class="toggle-label">
          <input type="checkbox" name="resolve" value="1" <?= !empty($_POST['resolve']) ? 'checked' : '' ?>>
          DNS resolution
        </label>
        <span class="hint">(resolves IPs &amp; domains &mdash; slower)</span>
      </div>
    </div>

    <div class="actions">
      <button type="submit" id="submit-btn">Analyse &#8594;</button>
    </div>
  </form>
  <?php endif; ?>

  <?php if ($processing && $result_html): ?>
    <div id="result-container">
      <iframe id="result-frame"
        sandbox="allow-popups allow-scripts"
        title="Analysis Result"></iframe>
    </div>
    <div class="back-link"><a href="<?= htmlspecialchars(strtok($_SERVER['REQUEST_URI'], '?')) ?>">&#8592; Analyse another</a></div>
    <script>
      (function () {
        const frame = document.getElementById('result-frame');
        const raw   = <?= json_encode($result_html) ?>;
        // Inject a postMessage height reporter into the srcdoc so the
        // parent can resize the iframe without allow-same-origin.
        const resizer = '<script>'
          + 'new ResizeObserver(function(){parent.postMessage({dshHeight:document.documentElement.scrollHeight},"*")}).observe(document.documentElement);'
          + 'window.addEventListener("load",function(){parent.postMessage({dshHeight:document.documentElement.scrollHeight},"*")});'
          + '<\/script>';
        frame.srcdoc = raw.replace(/<\/body>/i, resizer + '</body>');
        window.addEventListener('message', function (e) {
          if (e.data && typeof e.data.dshHeight === 'number') {
            frame.style.height = Math.max(600, e.data.dshHeight + 20) + 'px';
          }
        });
      })();
    </script>
  <?php endif; ?>

  <div class="resources-bar">
    Related tools:
    <a href="https://mxtoolbox.com/" target="_blank" rel="noopener">MXToolbox</a>
    <span class="resources-sep">|</span>
    <a href="https://mha.azurewebsites.net/" target="_blank" rel="noopener">Microsoft Message Header Analyser</a>
  </div>

  <footer>
    <p>
      v<?= APP_VERSION ?> &mdash;
      Analysis engine: <a href="https://github.com/mgeeky/decode-spam-headers" target="_blank" rel="noopener">decode-spam-headers.py</a> by <a href="https://twitter.com/mariuszbit" target="_blank" rel="noopener">@mariuszbit</a>
    </p>
    <p style="margin-top: 6px;">
      Built by <a href="https://github.com/Platima" target="_blank" rel="noopener">Platima Tinkers</a>
      &nbsp;|&nbsp; <a href="https://shop.plati.ma" target="_blank" rel="noopener">SBC Shop</a>
      &nbsp;|&nbsp; <a href="https://youtube.com/@PlatimaTinkers" target="_blank" rel="noopener">YouTube</a>
    </p>
  </footer>
</div>

<!-- (no client-side .msg parser — the library has Node.js dependencies that don't work in browsers) -->

<script>
(function () {
  const dropzone  = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const fileName  = document.getElementById('file-name');
  const taWrap    = document.getElementById('textarea-wrap');
  const ta        = document.getElementById('headers-input');
  const form      = document.getElementById('analyser-form');
  const submitBtn = document.getElementById('submit-btn');

  if (!form) return; // nothing to wire on the results page

  // Restore DNS-resolution preference across sessions
  const resolveChk = form.querySelector('input[name="resolve"]');
  if (resolveChk) {
    if (!resolveChk.checked && localStorage.getItem('smtp_resolve') === '1') {
      resolveChk.checked = true;
    }
    resolveChk.addEventListener('change', () => {
      localStorage.setItem('smtp_resolve', resolveChk.checked ? '1' : '0');
    });
  }

  // ------------------------------------------------------------------
  // Extract MIME header block from raw .eml text (everything before
  // the first blank line).
  // ------------------------------------------------------------------
  function extractHeaders(text) {
    const norm     = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const blankIdx = norm.indexOf('\n\n');
    return blankIdx === -1 ? norm : norm.substring(0, blankIdx);
  }

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload  = () => resolve(r.result);
      r.onerror = () => reject(new Error('File read failed'));
      r.readAsText(file);
    });
  }

  // ------------------------------------------------------------------
  // Shared: send a .msg file to the PHP extraction endpoint and return
  // the header string, or null on failure.
  // ------------------------------------------------------------------
  async function extractMsgHeadersFromServer(file) {
    const fd = new FormData();
    fd.append('msgfile', file);
    const csrfInput = form.querySelector('input[name="csrf_token"]');
    if (csrfInput) fd.append('csrf_token', csrfInput.value);
    const resp = await fetch('?action=extract_msg_headers', {
      method: 'POST',
      body: fd,
      headers: { 'X-CSRF-Token': csrfInput ? csrfInput.value : '' }
    });
    const data = await resp.json();
    if (data.ok && data.headers) return data.headers;
    throw new Error(data.error || 'Could not extract headers from this .msg file.');
  }

  // ------------------------------------------------------------------
  // Dropzone: visual hover
  // ------------------------------------------------------------------
  dropzone.addEventListener('dragover', e => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

  // Dropzone DROP:
  //   .eml / .txt → read in browser, strip to header block, auto-submit as text
  //   .msg → extract headers server-side, populate textarea, auto-submit
  const MAX_DROP_BYTES = 50 * 1024 * 1024; // 50 MB hard reject (avoid OOM)
  dropzone.addEventListener('drop', async e => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (!file) return;

    if (file.size > MAX_DROP_BYTES) {
      fileName.textContent = '\u26a0 ' + file.name + ' \u2014 file too large (max 50 MB)';
      return;
    }

    if (file.name.toLowerCase().endsWith('.msg')) {
      fileName.textContent = file.name + ' \u2014 extracting headers\u2026';
      try {
        const headers = await extractMsgHeadersFromServer(file);
        // Submit headers as text so Python gets clean RFC 822 input
        ta.value             = headers;
        fileInput.value      = '';
        fileName.textContent = file.name + ' \u2014 ';
        const s = document.createElement('span');
        s.className = 'anim-ellipsis'; s.textContent = 'submitting';
        fileName.appendChild(s);
        submitBtn.innerHTML = 'Analysing<span class="anim-ellipsis"></span>';
        submitBtn.disabled  = true;
        form.submit();
      } catch (err) {
        fileName.textContent = '\u26a0 ' + file.name + ' \u2014 ' + err.message;
      }
      return;
    }

    // .eml / plain text — strip to header block in browser, submit as text
    try {
      const text        = await readFileAsText(file);
      const hdrs        = extractHeaders(text);
      ta.value          = hdrs;
      fileInput.value   = '';
      fileName.textContent = file.name + ' \u2014 ';
      updateCharCounter();
      const span1 = document.createElement('span');
      span1.className = 'anim-ellipsis'; span1.textContent = 'submitting';
      fileName.appendChild(span1);
      submitBtn.innerHTML = 'Analysing<span class="anim-ellipsis"></span>';
      submitBtn.disabled  = true;
      form.submit();
    } catch (err) {
      fileName.textContent = '\u26a0 ' + file.name + ' \u2014 ' + err.message;
    }
  });

  // File picker change: show name, clear textarea, but don't auto-submit
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) {
      fileName.textContent = fileInput.files[0].name;
      ta.value = '';
    }
  });

  // ------------------------------------------------------------------
  // Textarea drop zone: extract headers and show for review.
  // Neither .eml nor .msg auto-submits — user clicks Analyse when ready.
  // Capture-phase listeners fire before the native textarea handler.
  // ------------------------------------------------------------------
  taWrap.addEventListener('dragover', e => {
    e.preventDefault();
    e.stopPropagation();
    taWrap.classList.add('dragover');
  }, true);

  taWrap.addEventListener('dragleave', e => {
    if (!taWrap.contains(e.relatedTarget)) {
      taWrap.classList.remove('dragover');
    }
  }, true);

  taWrap.addEventListener('drop', async e => {
    e.preventDefault();
    e.stopPropagation();
    taWrap.classList.remove('dragover');

    const file = e.dataTransfer.files[0];
    if (!file) return;

    if (file.name.toLowerCase().endsWith('.msg')) {
      fileName.textContent = file.name + ' \u2014 extracting headers\u2026';
      ta.value       = '';
      ta.placeholder = 'Extracting headers from .msg\u2026';
      try {
        const headers        = await extractMsgHeadersFromServer(file);
        ta.value             = headers;
        ta.style.height      = '50vh';
        ta.placeholder       = '';
        fileName.textContent = file.name + ' \u2014 headers extracted';
        fileInput.value      = '';
        ta.focus();
      } catch (err) {
        ta.value       = '';
        ta.placeholder = err.message + '\n\nPaste headers manually or drop the file on the top area to submit directly.';
        fileName.textContent = '\u26a0 ' + file.name + ' \u2014 extraction failed';
      }
      return;
    }

    // .eml / plain text — extract headers into the textarea, do NOT submit
    try {
      const text    = await readFileAsText(file);
      const headers = extractHeaders(text);
      ta.value      = headers;
      ta.style.height = '50vh';
      ta.focus();
      fileInput.value      = '';
      fileName.textContent = file.name + ' \u2014 headers extracted';
      updateCharCounter();
    } catch (err) {
      ta.placeholder = 'Failed to read file: ' + err.message;
    }
  }, true);

  // ------------------------------------------------------------------
  // Character counter for paste textarea
  // ------------------------------------------------------------------
  const charCount   = document.getElementById('char-count');
  const charCounter = document.getElementById('char-counter');
  const MAX_PASTE   = 50000;

  function updateCharCounter() {
    if (!charCount || !ta) return;
    const len = ta.value.length;
    charCount.textContent = len.toLocaleString();
    charCounter.classList.toggle('warn',  len > MAX_PASTE * 0.8 && len <= MAX_PASTE);
    charCounter.classList.toggle('limit', len > MAX_PASTE);
  }

  if (ta) {
    ta.addEventListener('input', updateCharCounter);
    updateCharCounter(); // initialise on page load (handles repopulated POST value)
  }

  // ------------------------------------------------------------------
  // Loading state on manual submit
  // ------------------------------------------------------------------
  form.addEventListener('submit', () => {
    submitBtn.innerHTML = 'Analysing<span class="anim-ellipsis"></span>';
    submitBtn.disabled  = true;
  });
})();
</script>
<script>
(function () {
  const toggle = document.getElementById('theme-toggle');
  const root   = document.documentElement;
  const stored = localStorage.getItem('smtp_theme');

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    toggle.innerHTML = theme === 'dark' ? '&#9788; Light' : '&#9790; Dark';
    localStorage.setItem('smtp_theme', theme);
  }

  // Initialise from stored preference (if any)
  if (stored) {
    applyTheme(stored);
  } else {
    // Match system preference; default to dark
    const preferLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    toggle.innerHTML = preferLight ? '&#9790; Dark' : '&#9788; Light';
  }

  toggle.addEventListener('click', function () {
    const current = root.getAttribute('data-theme')
                 || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });
})();
</script>
</body>
</html>

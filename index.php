<?php
// -----------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------
define('SCRIPT_PATH',     __DIR__ . '/decode-spam-headers.py');
define('MAX_INPUT_BYTES', 512 * 1024); // 512 KB sanity cap for file uploads
define('MAX_PASTE_CHARS', 50000);       // max characters for pasted headers
define('APP_VERSION',     '0.3.2');
define('DEBUG_MODE',      getenv('DSH_DEBUG') === '1');
define('RATE_LIMIT',      10);          // max requests per window
define('RATE_WINDOW',     60);          // seconds

// Resolve the Python binary once per request.
// Tests each candidate by actually executing it - avoids open_basedir restrictions.
// Stores per-candidate results in $GLOBALS['_python_diag'] for error reporting.
// Sets $GLOBALS['_python_via_login_shell'] to the shell path if CageFS login-shell
// wrapping is needed (CloudLinux/cPanel lsphp cage doesn't mount python directly).
function find_python_bin(): string {
    static $resolved = null;
    if ($resolved !== null) return $resolved;

    $GLOBALS['_python_diag'] = [];
    $GLOBALS['_python_via_login_shell'] = '';

    // Direct candidates: CloudLinux alt-python paths first, then standard paths.
    $candidates = [
        '/opt/alt/python312/bin/python3',
        '/opt/alt/python311/bin/python3',
        '/opt/alt/python310/bin/python3',
        '/opt/alt/python39/bin/python3',
        '/opt/alt/python38/bin/python3',
        '/opt/alt/python3/bin/python3',
        '/usr/local/cpanel/3rdparty/bin/python3',
        '/bin/python3',
        '/usr/bin/python3',
        '/usr/local/bin/python3',
        '/bin/python',
        '/usr/bin/python',
        '/usr/local/bin/python',
        'python3',
        'python',
    ];
    foreach ($candidates as $candidate) {
        $out = @shell_exec(escapeshellarg($candidate) . ' --version 2>&1');
        $hit = ($out !== null && strpos($out, 'Python') !== false);
        $GLOBALS['_python_diag'][] = [
            'candidate' => $candidate,
            'output'    => $out,
            'matched'   => $hit,
        ];
        if ($hit) {
            $resolved = $candidate;
            return $resolved;
        }
    }

    // CageFS fallback: on CloudLinux/cPanel the lsphp cage may not mount python,
    // but a login shell does. Try bash -l and sh -l.
    foreach (['/bin/bash', '/bin/sh'] as $sh) {
        // First discover the real path via login shell so we can report it.
        $found = trim((string)@shell_exec($sh . ' -l -c \'which python3 2>/dev/null || which python 2>/dev/null\' 2>&1'));
        $label = $sh . ' -l -c python3';
        if ($found !== '' && strpos($found, 'python') !== false && strpos($found, ' ') === false) {
            $label = $sh . ' -l → ' . $found;
        }

        // Verify it actually runs through login shell.
        $out = @shell_exec($sh . ' -l -c \'python3 --version 2>/dev/null || python --version 2>/dev/null\' 2>&1');
        $hit = ($out !== null && strpos($out, 'Python') !== false);
        $GLOBALS['_python_diag'][] = [
            'candidate' => $label . ' (login shell wrapper)',
            'output'    => $out,
            'matched'   => $hit,
        ];
        if ($hit) {
            $GLOBALS['_python_via_login_shell'] = $sh;
            // Return the discovered path if we have it, otherwise bare name.
            $resolved = ($found !== '' && strpos($found, 'python') !== false) ? $found : 'python3';
            return $resolved;
        }
    }

    $resolved = 'python3'; // last resort – error will surface in output
    return $resolved;
}

// Build an HTML diagnostics block for inclusion in error output.
function python_diagnostics_html(string $cmd): string {
    $dis   = ini_get('disable_functions') ?: '(none)';
    $test  = @shell_exec('echo __shell_test__ 2>&1');
    $id    = @shell_exec('id 2>&1');
    $path  = @shell_exec('echo $PATH 2>&1');
    $diag  = $GLOBALS['_python_diag'] ?? [];

    $rows = '';
    foreach ($diag as $d) {
        $out = $d['output'] === null ? '<em>null (exec blocked or binary missing)</em>'
             : htmlspecialchars(trim((string)$d['output']));
        $mark = $d['matched'] ? '&#10003;' : '&#x2715;';
        $rows .= '<tr><td>' . htmlspecialchars($d['candidate']) . '</td>'
               . '<td>' . $mark . '</td>'
               . '<td>' . $out . '</td></tr>';
    }

    return '<details style="margin-top:10px;font-size:0.75rem;"><summary style="cursor:pointer;font-weight:bold;">PHP/shell diagnostics (expand)</summary>'
        . '<table style="border-collapse:collapse;margin-top:6px;width:100%;" border="1" cellpadding="4">'
        . '<tr><th>PHP disable_functions</th><td colspan="2">' . htmlspecialchars($dis) . '</td></tr>'
        . '<tr><th>shell_exec test</th><td colspan="2">' . (strpos((string)$test, '__shell_test__') !== false ? 'OK' : 'FAILED - returned: ' . htmlspecialchars((string)$test)) . '</td></tr>'
        . '<tr><th>PHP process user</th><td colspan="2">' . htmlspecialchars((string)$id) . '</td></tr>'
        . '<tr><th>PATH seen by PHP</th><td colspan="2">' . htmlspecialchars((string)$path) . '</td></tr>'
        . '<tr><th>Command run</th><td colspan="2"><code>' . htmlspecialchars($cmd) . '</code></td></tr>'
        . '<tr><th>Python candidate</th><th>Match?</th><th>Output of --version</th></tr>'
        . $rows
        . '</table></details>';
}

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
// AJAX: health / dependency check (?action=healthz, GET, DEBUG_MODE only)
// Returns JSON with python binary path and missing pip packages.
// -----------------------------------------------------------------------
if (isset($_GET['action']) && $_GET['action'] === 'healthz') {
    if (!DEBUG_MODE) {
        http_response_code(403);
        echo json_encode(['error' => 'Enable DSH_DEBUG=1 to use this endpoint.']);
        exit;
    }
    header('Content-Type: application/json');

    $python = find_python_bin();
    $ver    = trim((string)@shell_exec(escapeshellarg($python) . ' --version 2>&1'));

    $pkgs   = ['python-dateutil', 'tldextract', 'packaging', 'dnspython', 'colorama', 'requests'];
    $status = [];
    foreach ($pkgs as $pkg) {
        $import = str_replace('-', '_', $pkg === 'python-dateutil' ? 'dateutil' : $pkg);
        $out = @shell_exec(escapeshellarg($python) . ' -c ' . escapeshellarg("import $import; print('ok')") . ' 2>&1');
        $status[$pkg] = (trim((string)$out) === 'ok') ? 'ok' : trim((string)$out);
    }

    echo json_encode([
        'python_binary'  => $python,
        'python_version' => $ver,
        'packages'       => $status,
        'script_exists'  => file_exists(SCRIPT_PATH),
    ], JSON_PRETTY_PRINT);
    exit;
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

        // Strip email body: if there is a blank line (header/body separator),
        // keep only the portion before it. Applies to both pasted text and
        // uploaded files, as a server-side safety net for the JS stripping.
        $separator = strpos($raw_headers, "\n\n");
        if ($separator !== false) {
            $raw_headers = trim(substr($raw_headers, 0, $separator));
        }

        if (empty($script_errors) && empty($raw_headers)) {
            $script_errors[] = 'No headers provided. Paste headers into the text box or upload an .eml / .msg file.';
        } elseif (empty($script_errors) && isset($_POST['headers']) && strlen($raw_headers) > MAX_PASTE_CHARS) {
            $script_errors[] = 'Pasted headers exceed the ' . number_format(MAX_PASTE_CHARS) . '-character limit. '
                . 'If you have a full .eml file, upload or drop it - the body is stripped automatically.';
        } elseif (empty($script_errors) && strlen($raw_headers) > MAX_INPUT_BYTES) {
            $script_errors[] = 'Input exceeds the 512 KB limit.';
        } elseif (empty($script_errors)) {
            $tmp = tempnam(sys_get_temp_dir(), 'dsh_');
            register_shutdown_function(function () use ($tmp) { @unlink($tmp); });
            file_put_contents($tmp, $raw_headers);

            $resolve_flag = !empty($_POST['resolve']) ? '-r' : '-R';
            $python = find_python_bin();
            $login_sh = $GLOBALS['_python_via_login_shell'] ?? '';

            if ($login_sh !== '') {
                // CageFS: python is only accessible via a login shell.
                // Build the inner command and wrap it in bash -l -c '...'
                $inner = 'DECODE_SPAM_HEADERS_WEB=1'
                       . ' ' . escapeshellarg($python)
                       . ' ' . escapeshellarg(SCRIPT_PATH)
                       . ' -f html'
                       . ' ' . $resolve_flag
                       . ' ' . escapeshellarg($tmp);
                $cmd = $login_sh . ' -l -c ' . escapeshellarg($inner) . ' 2>&1';
            } else {
                $cmd = 'DECODE_SPAM_HEADERS_WEB=1'
                     . ' ' . $python
                     . ' ' . escapeshellarg(SCRIPT_PATH)
                     . ' -f html'
                     . ' ' . $resolve_flag
                     . ' ' . escapeshellarg($tmp)
                     . ' 2>&1';
            }

            $output = shell_exec($cmd);
            @unlink($tmp);

            if ($output === null || $output === false) {
                $script_errors[] = 'Failed to execute the analysis script.'
                    . (DEBUG_MODE ? python_diagnostics_html($cmd) : ' Enable <code>DSH_DEBUG=1</code> on the server for details.');
            } else {
                $lines      = explode("\n", $output);
                $html_lines = [];
                $raw_output = $output;

                foreach ($lines as $line) {
                    if (preg_match('/^\s*\[!\]/', $line)) {
                        if (preg_match('/pip3 install (\S+)/', $line, $m)) {
                            $pkg = htmlspecialchars($m[1]);
                            $script_errors[] = 'Missing Python dependency: <code>' . $pkg . '</code> - '
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
                    $preview = htmlspecialchars(mb_substr(trim($raw_output), 0, 2048));
                    $script_errors[] = 'Script returned no recognisable output. '
                        . 'Python binary resolved to: <code>' . htmlspecialchars(find_python_bin()) . '</code>';
                    $script_errors[] = '<strong>Script output:</strong><pre style="white-space:pre-wrap;word-break:break-all;margin-top:6px;font-size:0.75rem;">'
                        . $preview . (strlen(trim($raw_output)) > 2048 ? '\n[... truncated]' : '') . '</pre>'
                        . (DEBUG_MODE ? python_diagnostics_html($cmd) : '<p style="font-size:0.75rem;margin-top:6px;">Enable <code>DSH_DEBUG=1</code> on the server for full diagnostics.</p>');
                    if (DEBUG_MODE) {
                        $script_errors[] = '<strong>Full debug output:</strong><pre style="white-space:pre-wrap;word-break:break-all;margin-top:8px;">'
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
<link rel="icon" type="image/svg+xml" href="img/favicon.svg">
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

  .result-actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-bottom: 10px;
  }

  .copy-btn {
    background: none;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--muted);
    font-family: var(--sans);
    font-size: 0.75rem;
    padding: 4px 12px;
    cursor: pointer;
    transition: color 0.15s, border-color 0.15s;
  }
  .copy-btn:hover { color: var(--text); border-color: var(--accent2); }
  .copy-btn.copied { color: var(--accent); border-color: var(--accent); }

  footer {
    margin-top: 40px;
    font-size: 0.68rem;
    color: var(--muted);
    text-align: center;
    letter-spacing: 0.06em;
  }

  footer a { color: var(--accent2); text-decoration: none; }
  footer a:hover { text-decoration: underline; }

  /* Changelog modal */
  .modal-backdrop {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 200;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .modal-backdrop.open { display: flex; }

  .modal {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    width: 100%;
    max-width: 680px;
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 22px 14px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .modal-title {
    font-family: var(--sans);
    font-weight: 700;
    font-size: 1rem;
    color: var(--heading);
  }

  .modal-close {
    background: none;
    border: none;
    cursor: pointer;
    color: var(--muted);
    font-size: 1.2rem;
    line-height: 1;
    padding: 2px 6px;
    border-radius: 4px;
    transition: color 0.15s;
  }
  .modal-close:hover { color: var(--text); }

  .modal-body {
    overflow-y: auto;
    padding: 18px 22px 22px;
    font-size: 0.8rem;
    line-height: 1.7;
    color: var(--text);
  }

  .cl-version {
    font-family: var(--sans);
    font-weight: 700;
    font-size: 0.82rem;
    color: var(--accent);
    margin-top: 18px;
    margin-bottom: 4px;
  }
  .cl-version:first-child { margin-top: 0; }

  .cl-version span {
    color: var(--muted);
    font-weight: 400;
    font-size: 0.72rem;
    margin-left: 8px;
  }

  .modal-body ul {
    margin: 0;
    padding-left: 18px;
  }

  .modal-body li { margin-bottom: 2px; }

  .modal-footer-link {
    padding: 12px 22px;
    border-top: 1px solid var(--border);
    font-size: 0.72rem;
    color: var(--muted);
    flex-shrink: 0;
  }
  .modal-footer-link a { color: var(--accent2); text-decoration: none; }
  .modal-footer-link a:hover { text-decoration: underline; }

  .changelog-btn {
    background: none;
    border: none;
    cursor: pointer;
    font-family: var(--sans);
    font-size: inherit;
    color: var(--accent2);
    padding: 0;
    text-decoration: underline dotted;
  }
  .changelog-btn:hover { color: var(--accent); }

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
        <span class="dz-icon">&#128231;</span>
        <p><strong>Drop an .eml or .msg file here to analyse immediately</strong><br>or click to browse</p>
        <p class="dz-sub">.eml body is stripped automatically &nbsp;|&nbsp; .msg headers are extracted first, then submitted</p>
      </div>
      <div id="file-name"></div>

      <div class="divider">or paste / drop headers below</div>

      <div class="textarea-wrap" id="textarea-wrap">
        <textarea name="headers" id="headers-input" maxlength="50000"
          placeholder="Received: from mail-wr1-f99.google.com ...&#10;X-Forefront-Antispam-Report: CIP:209.85.222.99; ...&#10;&#10;Paste raw email headers here, or drop a file above."
        ><?= htmlspecialchars($_POST['headers'] ?? '') ?></textarea>
        <div class="char-counter" id="char-counter"><span id="char-count">0</span>&nbsp;/&nbsp;50,000 <span id="paste-notice" style="display:none;margin-left:8px;color:var(--accent);font-size:0.72rem;">Body stripped</span></div>
        <div class="textarea-drop-hint">&#8595; Drop .eml or .msg to extract headers</div>
      </div>

      <div class="options">
        <label class="toggle-label">
          <input type="checkbox" name="resolve" value="1" <?= !empty($_POST['resolve']) ? 'checked' : '' ?>>
          DNS resolution
        </label>
        <span class="hint">(resolves IPs &amp; domains - slower)</span>
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
    <div class="result-actions">
      <button class="copy-btn" id="copy-btn">Copy analysis</button>
      <a class="copy-btn" style="text-decoration:none;" href="<?= htmlspecialchars(strtok($_SERVER['REQUEST_URI'], '?')) ?>">&#8592; Analyse another</a>
    </div>
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

        // Copy-to-clipboard: extract plain text from the iframe HTML
        document.getElementById('copy-btn').addEventListener('click', function () {
          var btn = this;
          // Strip tags and decode entities from the result HTML
          var tmp = document.createElement('div');
          tmp.innerHTML = raw;
          var text = (tmp.innerText || tmp.textContent || '').trim();
          navigator.clipboard.writeText(text).then(function () {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function () {
              btn.textContent = 'Copy analysis';
              btn.classList.remove('copied');
            }, 2000);
          }).catch(function () {
            // Fallback for older browsers / non-HTTPS
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function () {
              btn.textContent = 'Copy analysis';
              btn.classList.remove('copied');
            }, 2000);
          });
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
      <button class="changelog-btn" id="changelog-btn">v<?= APP_VERSION ?></button> -
      Analysis engine: <a href="https://github.com/mgeeky/decode-spam-headers" target="_blank" rel="noopener">decode-spam-headers.py</a> by <a href="https://twitter.com/mariuszbit" target="_blank" rel="noopener">@mariuszbit</a>
    </p>
    <p style="margin-top: 6px;">
      Built by <a href="https://github.com/Platima" target="_blank" rel="noopener">Platima Tinkers</a>
      &nbsp;|&nbsp; <a href="https://shop.plati.ma" target="_blank" rel="noopener">SBC Shop</a>
      &nbsp;|&nbsp; <a href="https://youtube.com/@PlatimaTinkers" target="_blank" rel="noopener">YouTube</a>
    </p>
  </footer>
</div>

<!-- Changelog modal -->
<div class="modal-backdrop" id="changelog-modal" role="dialog" aria-modal="true" aria-label="Changelog">
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title">Changelog</div>
      <button class="modal-close" id="changelog-close" aria-label="Close">&times;</button>
    </div>
    <div class="modal-body">
      <div class="cl-version">0.3.2 <span>2026-04-22</span></div>
      <ul>
        <li>TOC always expanded by default (no click required)</li>
        <li>TOC no longer shows duplicate numbers (removed redundant ordered-list counter)</li>
        <li>Removed &ldquo;SMTP Headers analysis by decode-spam-headers.py&rdquo; title and <code>@mariuszbit</code> attribution from results page (credit remains in app footer)</li>
        <li>Removed extra blank lines before and after the Original SMTP Headers section</li>
        <li>Suppressed &ldquo;Experiencing a bad-looking output&rdquo; console hint in web mode</li>
      </ul>
      <div class="cl-version">0.3.1 <span>2026-04-22</span></div>
      <ul>
        <li>Paste auto-strips email body: text pasted into the header box is truncated at the first blank line; brief &ldquo;Body stripped&rdquo; notice shown</li>
        <li>Server-side body strip: PHP also truncates at the blank-line separator as a safety net</li>
      </ul>
      <div class="cl-version">0.3.0 <span>2026-04-22</span></div>
      <ul>
        <li>Copy-to-clipboard button on results page</li>
        <li>Diagnostics block gated behind <code>DSH_DEBUG=1</code> (security)</li>
        <li><code>?action=healthz</code> endpoint for dependency verification (debug mode)</li>
        <li>README: self-hosting dependency check documented</li>
      </ul>
      <div class="cl-version">0.2.9 <span>2026-04-22</span></div>
      <ul>
        <li>SVG favicon added (Solarised envelope)</li>
      </ul>
      <div class="cl-version">0.2.8 <span>2026-04-22</span></div>
      <ul>
        <li>Fix ANSI escape codes appearing in HTML output (suppress logger stderr in web mode)</li>
        <li>Fix stray <code>&lt;/font&gt;</code> text from nested colour markers - depth-tracking split replaces non-greedy regex</li>
        <li>21/21 tests passing</li>
      </ul>
      <div class="cl-version">0.2.7 <span>2026-04-22</span></div>
      <ul>
        <li>Changelog modal in footer (closes on &times;, backdrop click, or Escape)</li>
        <li>CageFS/CloudLinux python detection fix: checks <code>/opt/alt/pythonXXX</code> paths then login shell fallback</li>
      </ul>
      <div class="cl-version">0.2.6 <span>2026-04-22</span></div>
      <ul>
        <li>Auto-detect <code>python3</code>/<code>python</code> binary at runtime</li>
        <li>Error output now reports which Python binary was resolved</li>
        <li>Dropzone icon changed from lock to envelope</li>
        <li>Instructions moved to <code>.github/copilot-instructions.md</code></li>
        <li>Version bump discipline corrected to semver 0.x.y</li>
      </ul>
      <div class="cl-version">0.2.5 <span>2026-04-22</span></div>
      <ul>
        <li>Character counter now updates when dropping a file on the textarea</li>
        <li>Header tagline removed (credit retained in footer)</li>
        <li>All em dashes replaced with regular dashes throughout</li>
        <li>Script failure now always shows raw Python output snippet for diagnosis</li>
      </ul>
      <div class="cl-version">0.2.4 <span>2026-04-22</span></div>
      <ul>
        <li>File drop limit raised to 50 MB</li>
        <li>Paste limit raised to 50,000 characters</li>
      </ul>
      <div class="cl-version">0.2.3 <span>2026-04-22</span></div>
      <ul>
        <li>XSS fix: HTML-escape plain-text header values and raw headers block in Python output</li>
        <li>Paste size limit: 50k-char cap with live counter, client maxlength, and server-side check</li>
        <li>.eml body stripped in browser before submission; 50 MB hard reject on drop</li>
        <li>Related resources bar: MXToolbox and Microsoft Message Header Analyser</li>
        <li>16/16 pytest suite added</li>
        <li><code>.gitignore</code> added</li>
      </ul>
      <div class="cl-version">0.2.2 <span>2026-04-22</span></div>
      <ul>
        <li>Security: CSRF tokens, rate limiting (10 req/min), iframe sandbox fix, HTTP security headers</li>
        <li>Debug mode restricted to <code>DSH_DEBUG=1</code> env var</li>
        <li>Server-side file type validation; temp file cleanup on shutdown</li>
        <li>Solarised Dark/Light theme with system preference detection and manual toggle</li>
        <li>Intel One Mono + Source Sans 3 fonts</li>
        <li>Platima Tinkers credits in footer</li>
      </ul>
      <div class="cl-version">0.2.1 <span>2026-04-22</span></div>
      <ul>
        <li>Python import stubs gated on <code>DECODE_SPAM_HEADERS_WEB=1</code> env var</li>
        <li>Table of Contents injected in web mode only</li>
        <li>Nested colour marker bug fix; UTF-8 encoding fix</li>
      </ul>
      <div class="cl-version">0.2.0 <span>2026-04-22</span></div>
      <ul>
        <li>Initial Platima fork of mgeeky/decode-spam-headers</li>
        <li>PHP web interface created; README and FUNDING added</li>
      </ul>
    </div>
    <div class="modal-footer-link">
      Full history: <a href="https://github.com/Platima/smtp-header-viewer/commits/main" target="_blank" rel="noopener">github.com/Platima/smtp-header-viewer</a>
    </div>
  </div>
</div>

<!-- (no client-side .msg parser - the library has Node.js dependencies that don't work in browsers) -->

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

    // .eml / plain text - strip to header block in browser, submit as text
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
  // Neither .eml nor .msg auto-submits - user clicks Analyse when ready.
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
        updateCharCounter();
        ta.focus();
      } catch (err) {
        ta.value       = '';
        ta.placeholder = err.message + '\n\nPaste headers manually or drop the file on the top area to submit directly.';
        fileName.textContent = '\u26a0 ' + file.name + ' \u2014 extraction failed';
      }
      return;
    }

    // .eml / plain text - extract headers into the textarea, do NOT submit
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

    // Strip email body on paste: if the pasted text contains a blank line
    // (header/body separator) truncate to the header block only.
    ta.addEventListener('paste', function (e) {
      const pasted = (e.clipboardData || window.clipboardData).getData('text');
      if (!pasted) return; // let browser handle empty paste normally

      const stripped = extractHeaders(pasted);
      if (stripped.length < pasted.trim().length) {
        e.preventDefault();
        // Replace the full textarea value so we don't append into existing content
        const start = ta.selectionStart;
        const before = ta.value.substring(0, start);
        const after  = ta.value.substring(ta.selectionEnd);
        ta.value = (before + stripped + after).substring(0, MAX_PASTE);
        // Move caret to end of insertion
        const newPos = Math.min(start + stripped.length, ta.value.length);
        ta.setSelectionRange(newPos, newPos);
        updateCharCounter();
        // Brief notice
        const notice = document.getElementById('paste-notice');
        if (notice) {
          notice.style.display = 'inline';
          clearTimeout(notice._t);
          notice._t = setTimeout(() => { notice.style.display = 'none'; }, 4000);
        }
      }
    });
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
<script>
(function () {
  const modal  = document.getElementById('changelog-modal');
  const btn    = document.getElementById('changelog-btn');
  const close  = document.getElementById('changelog-close');
  if (!modal || !btn) return;

  function openModal()  { modal.classList.add('open');    document.body.style.overflow = 'hidden'; }
  function closeModal() { modal.classList.remove('open'); document.body.style.overflow = ''; }

  btn.addEventListener('click', openModal);
  close.addEventListener('click', closeModal);
  // Click outside the inner modal panel to close
  modal.addEventListener('click', function (e) { if (e.target === modal) closeModal(); });
  // Escape key
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModal(); });
})();
</script>
</body>
</html>

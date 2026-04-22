# SMTP Header Analyser: Copilot Instructions

## Project Overview
A PHP + Python web tool hosted at **smtpheaders.com** for analysing SMTP headers.
Fork of [mgeeky/decode-spam-headers](https://github.com/mgeeky/decode-spam-headers).

- `index.php` — PHP frontend, request handler, .msg extraction endpoint
- `decode-spam-headers.py` — Python analysis engine (forked from @mgeeky, patched for web use)
- `correlate-rules.py` — Supplementary CLI tool for correlating O365 anti-spam rules (upstream)

## Conventions
- **Australian English** throughout (analyse, colour, honour, etc.)
- **No double hyphens** (`--`) or em dashes in prose. Use a single dash or rephrase.
- **Solarised colour scheme** (dark default, light mode supported)
- **Semver**: bump patch for fixes, minor for new features, major for breaking changes
- **Git**: commit after each logical change, push after each complete release set
- **Fonts**: Intel One Mono (monospace), Source Sans 3 (sans-serif)

## Version Number
**Always bump `APP_VERSION` in `index.php` when making any user-facing change.**

Current version: `1.18`

### Version history
- 1.0 to 1.16 — Initial build through nested colour marker fix (see git log)
- 1.17 — Security hardening (CSRF, rate limiting, iframe sandbox, security headers, debug restriction, file validation, temp cleanup); Solarised dark/light theme; Intel One Mono fonts; conditional Python import stubs (env var gated); Platima Tinkers credits
- 1.18 — XSS fix (HTML-escape uncoloured header values and raw headers block in Python output); paste size limit (30k chars, client + server); .eml body stripped in browser before submit; related resources section (MXToolbox, Microsoft MHA); 16/16 tests passing

## Key Architecture

### Security
- **CSRF**: session-based token on all POST forms and AJAX endpoints
- **Rate limiting**: file-based per-IP throttle (10 req/min default)
- **Iframe sandbox**: `allow-popups allow-scripts` only (no `allow-same-origin`); auto-resize via `postMessage`
- **Debug mode**: gated on `DSH_DEBUG=1` env var, not query string
- **HTTP headers**: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **File validation**: server-side extension check (.eml, .msg, .txt)
- **Cloudflare WAF**: expected in front; app-level validation still essential (WAF cannot inspect file upload bodies)

### Python integration
The PHP frontend sets `DECODE_SPAM_HEADERS_WEB=1` in the shell environment when calling the Python script.
This env var gates:
- **Import stubs**: missing dependencies get graceful fallbacks instead of `sys.exit(1)`
- **TOC feature**: Table of Contents injected into HTML output (web mode only)
- CLI mode (no env var) preserves original upstream behaviour

### .msg Browser Parsing
**DO NOT attempt with JS libraries.** `@kenjiuno/msgreader` and similar npm parsers depend on Node.js built-ins.
The correct solution is the PHP AJAX endpoint (`?action=extract_msg_headers`) that scans the OLE2 binary for RFC 822 headers.

### File upload flow
1. **Top dropzone**: .eml auto-submits; .msg extracts headers server-side then submits
2. **Textarea dropzone**: .eml/.msg extracts headers into textarea for review; user clicks Analyse

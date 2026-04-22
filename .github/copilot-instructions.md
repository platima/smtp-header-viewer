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
- **Semver**: `0.x.y` while pre-stable. Bump patch (`y`) for fixes, minor (`x`) for new features, major only for breaking changes. **Always bump `APP_VERSION` in `index.php` on every user-facing change** - do not leave it at the previous value.
- **Git**: commit after each logical change, push after each complete release set
- **Fonts**: Intel One Mono (monospace), Source Sans 3 (sans-serif)

## Version Number
**Always bump `APP_VERSION` in `index.php` when making any user-facing change.**

Current version: `0.3.1`

### Version history
- 0.1.x - upstream mgeeky/decode-spam-headers (see upstream git log)
- 0.2.0 - initial Platima fork; crude index.php created; README/FUNDING added
- 0.2.1 - Python upstream compatibility (import stubs, TOC gated on env var, bug fixes)
- 0.2.2 - Security hardening (CSRF, rate limiting, iframe sandbox, HTTP headers, debug restriction, file validation, temp cleanup); Solarised dark/light theme; Intel One Mono fonts; Platima Tinkers credits
- 0.2.3 - XSS fix (HTML-escape header values and raw block in Python output); paste 50k-char limit; .eml body stripped in browser; related resources (MXToolbox, Microsoft MHA); 16/16 tests; .gitignore
- 0.2.4 - Drop limit 50 MB, paste limit 50k chars
- 0.2.5 - Fix char counter on drop; remove header tagline; replace all em dashes; always show Python output snippet on failure
- 0.2.6 - Auto-detect python3/python binary; envelope emoji; move instructions to .github/copilot-instructions.md; semver corrected to 0.x.y
- 0.2.7 - Changelog modal in footer (version history, closes on X/backdrop/Escape, links to GitHub); CageFS/CloudLinux python detection fix
- 0.2.8 - Fix ANSI codes in HTML output (suppress logger stderr in web mode); fix stray </font> text from nested colour markers (depth-tracking split); 21/21 tests
- 0.2.9 - SVG favicon (Solarised envelope, img/favicon.svg)
- 0.3.0 - Copy-to-clipboard on results; diagnostics gated behind DSH_DEBUG=1; ?action=healthz dependency check endpoint; README self-hosting docs
- 0.3.1 - Paste strips email body (JS on paste event + PHP server-side safety net); "Body stripped" notice shown

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

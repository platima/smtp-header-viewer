# SMTP Decoder – Copilot Instructions

## Project Overview
A PHP + Python internal web tool for analysing SMTP headers.
- `index.php` — PHP frontend/UI and request handler
- `decode-spam-headers.py` — Python analysis engine (3rd-party script by @mgeeky, lightly patched)

## Version Number
**Always bump `APP_VERSION` in `index.php` when making any user-facing change.**

Current version: `1.16`

Version history (semver — bump patch for fixes, minor for new features, major for breaking changes):
- 1.0 — Initial build
- 1.1 — colorama stub
- 1.2 — Textarea drop capture-phase fix; all missing Python deps stubbed
- 1.3 — .msg blocking; ?debug=1 mode; better error messages; width 80vw
- 1.4 — msgreader CDN for .msg textarea drop; TOC in analysis output
- 1.5 — Fixed msgreader CDN URL (404); .msg allowed on top dropzone
- 1.6 — Python open() with errors='replace'; debug link clickable
- 1.7 — iframe allow-scripts for TOC; MSGReader CJS shim attempt
- 1.8 — Removed MSGReader; TOC scrollIntoView
- 1.9 — Animated ellipsis; h1 links to current path; .eml textarea drop populates without auto-submitting
- 1.11 — Removed MSGReader permanently (has Node.js internals, cannot run in any browser)
- 1.12 — .msg header extraction via PHP AJAX endpoint (?action=extract_msg_headers)
- 1.13 — Both drop zones use same PHP extraction for .msg; top dropzone auto-submits after extraction; textarea shows headers for review; shared extractMsgHeadersFromServer() helper
- 1.14 — Fixed .msg header extraction truncating at headers with empty inline values (e.g. X-MS-Has-Attach)
- 1.15 — Fixed nested colour tags showing as literal HTML (double-escape in htmlColors); DNS resolution checkbox persists via localStorage; textarea expands to 50vh on drop
- 1.16 — Properly fixed nested colour markers: replaceColors now processes innermost markers first, eliminating dangling </font> tags and &lt;&gt; escaping on From/To angle brackets

## ⚠ .msg Browser Parsing — DO NOT ATTEMPT WITH JS LIBRARIES
`@kenjiuno/msgreader` and ALL similar npm .msg parsers depend on Node.js built-ins
(`internal.js`, `Buffer`, `require`, etc). They CANNOT be made to work in a browser.
The correct solution is a PHP AJAX endpoint (`?action=extract_msg_headers`) that:
  1. Receives the file via FormData POST
  2. Scans the binary for the largest RFC 822 header block (plain ASCII inside OLE2)
  3. Returns JSON `{ok, headers, error}`
  4. JS populates the textarea — user reviews and clicks Analyse manually

Version history:
- 1.0 — Initial build
- 1.1 — colorama stub (no sys.exit on missing dep)
- 1.2 — Textarea drop capture-phase fix; all missing Python deps stubbed
- 1.3 — .msg blocking; ?debug=1 mode; better error messages; width 80vw
- 1.4 — msgreader CDN for .msg textarea drop; TOC in analysis output
- 1.5 — Fixed msgreader CDN URL (404); .msg allowed on top dropzone
- 1.6 — Python open() with errors='replace'; MSGReader ESM attempt; debug link clickable
- 1.7 — iframe allow-scripts for TOC; MSGReader CJS shim attempt
- 1.8 — Removed MSGReader; .msg textarea drop submits via file input; TOC scrollIntoView
- 1.9 — Animated ellipsis on submitting/analysing; h1 links to /; .eml textarea drop populates without auto-submitting
- 2.0 — MSGReader restored with data-cfasync="false" CJS shim; both .eml and .msg on textarea extract headers for review before submit; fallback to direct submit if MSGReader unavailable

## Known Quirks — Cloudflare Rocket Loader
Rocket Loader rewrites `<script>` execution order and breaks CJS globals.
The ONLY reliable loading pattern for MsgReader.min.js is three separate tags ALL with `data-cfasync="false"`:
```html
<script data-cfasync="false">var module={exports:{}};var exports=module.exports;</script>
<script data-cfasync="false" src="...MsgReader.min.js"></script>
<script data-cfasync="false">window.MSGReader=module.exports.default||module.exports.MsgReader||module.exports;</script>
```
Do NOT use `type="module"`, `onload=` attribute, or inline the shim with the src tag.

The result iframe needs `allow-scripts` in its sandbox for TOC onclick to work.

## Key Architecture Notes

### Python dependencies
The host does not have pip access. All third-party imports in `decode-spam-headers.py` are wrapped
in `try/except ImportError` with **no-op stubs** — never `sys.exit(1)`. Stubbed packages:
- `colorama` — no-op init/deinit
- `packaging` — minimal version tuple comparator
- `requests` — raises RuntimeError (only used in optional tenant lookups, all wrapped in try/except)
- `tldextract` — returns empty domain fields
- `dnspython` — raises Exception (only used when -r DNS resolve flag is set)
- `python-dateutil` — falls back to `email.utils.parsedate_to_datetime`

### File upload flow
1. User drops `.eml` or `.msg` onto the **top dropzone** → PHP receives file → passed as temp file to Python script
2. User drops `.eml` or `.msg` onto the **textarea** → parsed client-side (msgreader for .msg, FileReader for .eml) → headers extracted → textarea populated → user clicks Analyse

### .msg files
- Top dropzone: submitted as binary to PHP/Python (Python script handles it natively)
- Textarea: parsed in-browser via `@kenjiuno/msgreader` from jsDelivr CDN
  - CDN URL: `https://cdn.jsdelivr.net/npm/@kenjiuno/msgreader@1/lib/MsgReader.min.js`
  - Global: `MSGReader`

### Output rendering
- Python script is called with `-f html` flag, output is an HTML document
- PHP strips `[!]` warning lines and renders the HTML in a sandboxed `<iframe srcdoc>`
- `?debug=1` GET param shows raw Python output when no HTML is produced

### TOC
`formatToHtml()` in `decode-spam-headers.py` injects anchor `id`s on each test `<div>` and
prepends a sticky collapsible TOC nav bar. Regex runs **before** space/newline HTML encoding.

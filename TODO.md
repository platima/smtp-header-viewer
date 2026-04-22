# TODO

## Done

- [x] **COPILOT.md update** - Solarised colour scheme, semver, Australian English, no em dashes, commit/push conventions
- [x] **README.md rewrite** - web interface intro (smtpheaders.com), self-hosting instructions, credits, CLI usage secondary. _Screenshots need retaking after launch._
- [x] **Python upstream compatibility** - import stubs gated on `DECODE_SPAM_HEADERS_WEB` env var; CLI mode preserves original `sys.exit(1)` behaviour; TOC feature conditional on web mode
- [x] **correlate-rules.py** - kept in repo, documented as supplementary CLI tool in README
- [x] **requirements.txt** - kept as-is (Python deps still needed)
- [x] **Bug fixes** - nested colour marker fix, `open()` encoding fix, dateutil stub bare except now logs warning
- [x] **Rate limiting** - file-based per-IP throttle (10 req/min); Cloudflare rate limiting recommended on top
- [x] **Security review** - CSRF tokens, iframe sandbox fix, HTTP security headers, debug mode restricted to env var, server-side file type validation, temp file cleanup, POST method check on MSG endpoint
- [x] **XSS fix** - HTML-escape plain-text segments in Python HTML output (uncoloured header values) and raw headers block; 16/16 tests pass
- [x] **Cloudflare WAF** - documented considerations (rate limiting rules on POST, cache bypass, Turnstile recommended, WAF cannot inspect upload bodies)
- [x] **Fonts** - Intel One Mono (monospace), Source Sans 3 (sans-serif)
- [x] **Dark/light mode** - Solarised Dark/Light, system preference detection, manual toggle with localStorage persistence
- [x] **Platima Tinkers credits** - footer with SBC Shop, YouTube, GitHub links
- [x] **CODE_OF_CONDUCT.md** - updated enforcement contact to Platima Tinkers
- [x] **LICENSE** - added Platima Tinkers copyright alongside original MIT
- [x] **Test suite** - Python unit tests covering header parsing, HTML output, colour replacement, import stubs, TOC, XSS, oversized input; all 16 pass
- [x] **Delete original comparison file** - `decode-spam-headers - original.py` removed
- [x] **Related resources** - MXToolbox and Microsoft Message Header Analyser links on homepage
- [x] **Paste size limit** - 30,000-character cap on textarea (client-side counter + maxlength + server-side check); uploads strip to header block in browser before submit
- [x] **Drop file handling** - .eml body stripped in browser before submission; 20 MB hard reject; .msg server-side extraction unchanged

## Future

- [ ] **Better test header** - replace `tests/fixtures/sample.eml` with a richer real-world capture (IPs/domains/names anonymised)
- [ ] **New screenshots** - retake after the web UI is deployed at smtpheaders.com
- [ ] **Metrics/analytics** - recommended: Cloudflare Analytics (free, no code changes, privacy-friendly). Alternative: Plausible or Umami (self-hosted)
- [ ] **Cloudflare Turnstile** - CAPTCHA/challenge on the form to reduce bot abuse (minimal code: JS widget + PHP verification)
- [ ] **Upstream PR** - submit `replaceColors`/`htmlColors` nested colour fix, `open()` encoding fix, and XSS escape fix as separate PRs to mgeeky/decode-spam-headers
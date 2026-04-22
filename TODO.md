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
- [x] **Cloudflare WAF** - documented considerations (rate limiting rules on POST, cache bypass, Turnstile recommended, WAF cannot inspect upload bodies)
- [x] **Fonts** - Intel One Mono (monospace), Source Sans 3 (sans-serif)
- [x] **Dark/light mode** - Solarised Dark/Light, system preference detection, manual toggle with localStorage persistence
- [x] **Platima Tinkers credits** - footer with SBC Shop, YouTube, GitHub links
- [x] **CODE_OF_CONDUCT.md** - updated enforcement contact to Platima Tinkers
- [x] **LICENSE** - added Platima Tinkers copyright alongside original MIT

## In Progress

- [ ] **Test suite** - Python unit tests (header parsing, colour replacement, HTML output, import stubs); PHP integration tests (uploads, CSRF, rate limiting, file validation, .msg extraction); security tests (XSS payloads, oversized input, malformed files)
- [ ] **Delete original comparison file** - `decode-spam-headers - original.py` can be removed now that Python changes are done

## Future

- [ ] **New screenshots** - retake after the web UI is deployed at smtpheaders.com
- [ ] **Metrics/analytics** - recommended: Cloudflare Analytics (free, no code changes, privacy-friendly). Alternative: Plausible or Umami (self-hosted)
- [ ] **Cloudflare Turnstile** - CAPTCHA/challenge on the form to reduce bot abuse (minimal code: JS widget + PHP verification)
- [ ] **Upstream PR** - submit `replaceColors`/`htmlColors` nested colour fix and `open()` encoding fix as separate PRs to mgeeky/decode-spam-headers
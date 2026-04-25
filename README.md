<img align="right" src="https://visitor-badge.laobi.icu/badge?page_id=platima.smtpheaders" height="20" />

# SMTP Header Analyser

**<p align="center">A web-based SMTP header analysis tool hosted at [smtpheaders.com](https://smtpheaders.com).</p>**

Paste raw email headers or drop / upload `.eml` or `.msg` files (max 50MB) and get a detailed breakdown of anti-spam verdicts, mail server hops, SPF/DKIM results, domain impersonation checks, and more. Powered by **105+ tests** across **85+ header types**.

Privacy is maintained by no submitted data being stored on the servers, and the email body being automatically stripped before submission.

This is a fork of [mgeeky/decode-spam-headers](https://github.com/mgeeky/decode-spam-headers) wrapped in a PHP web frontend with security hardening, a Solarised colour theme, dark/light mode support, and upstream-compatible Python changes.


## Web Usage

1. Visit **[smtpheaders.com](https://smtpheaders.com)**
2. Paste raw SMTP headers into the text box, or drag and drop an `.eml` / `.msg` file
3. Optionally enable **DNS resolution** (resolves IPs and domains; slower)
4. Click **Analyse**

`.eml` files dropped on the top dropzone auto-submit. `.msg` files have their headers extracted server-side first, then you review and submit.

> **Screenshots coming soon** (the old CLI screenshots below are from the upstream project).


## Features

- **105+ analysis tests** across 85+ SMTP header types
- **Office365 ForeFront** anti-spam rule decoding (including reverse-engineered opaque SFS/ENG rules)
- **Domain impersonation** detection with SPF and reverse-DNS checks
- **Mail server hop** visualisation from `Received` headers
- **Table of Contents** for navigating large reports
- Supports `.eml`, `.msg` (OLE2 header extraction), and raw pasted headers
- Dark and light mode (Solarised colour scheme, follows system preference)
- Per-session CSRF protection, IP-based rate limiting, sandboxed output


## Self-Hosting

### Requirements

- PHP 8.0+ with `session`, `json`, `fileinfo` extensions
- Python 3.8+ with dependencies from `requirements.txt`
- A web server (Apache, Nginx, etc.)

### Setup

```bash
git clone https://github.com/platima/smtp-header-viewer.git
cd smtp-header-viewer
pip3 install -r requirements.txt
```

Point your web server's document root at the cloned directory. The entry point is `index.php`.

### Verifying dependencies

With `DSH_DEBUG=1` set in the server environment, visit `/?action=healthz` to get a JSON report of the resolved Python binary, its version, and whether each required package is importable:

```json
{
  "python_binary": "/bin/python3",
  "python_version": "Python 3.12.12",
  "packages": {
    "python-dateutil": "ok",
    "tldextract": "ok",
    "packaging": "ok",
    "dnspython": "ok",
    "colorama": "ok",
    "requests": "ok"
  },
  "script_exists": true
}
```

If any package shows an error rather than `"ok"`, install it:

```bash
pip3 install <package-name> --break-system-packages
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DSH_DEBUG` | `0` | Set to `1` to enable debug output on errors |
| `DECODE_SPAM_HEADERS_WEB` | _(unset)_ | Set automatically by `index.php`; gates Python import stubs and TOC |

### Cloudflare considerations

The site is designed to sit behind Cloudflare WAF:
- **Rate limiting**: add a rule on POST requests (the app also rate-limits server-side)
- **Caching**: bypass cache for POST responses
- **Turnstile/challenge**: recommended for bot protection on the form
- **Note**: Cloudflare WAF cannot inspect file upload bodies, so app-level validation is essential


## CLI Usage

The Python script also works standalone as a CLI tool (original upstream behaviour):

```bash
pip3 install -r requirements.txt
python3 decode-spam-headers.py headers.txt
python3 decode-spam-headers.py headers.txt -f html -o report.html
python3 decode-spam-headers.py --help
```

### Supplementary tools

- `correlate-rules.py` — batch correlation of Office365 anti-spam rule IDs across multiple analysis outputs (CLI only, not part of the web interface)


## Example Output

> These screenshots are from the upstream CLI tool. Web interface screenshots will be added after launch.

- Chain of MTA servers (parsed `Received` headers):

![1.png](img/1.png)

- Office365 ForeFront Spam Report decoding:

![2.png](img/2.png)

- Domain Impersonation detection:

![3.png](img/3.png)

- Anti-spam rule reverse-engineering:

![4.png](img/4.png)

- HTML report output:

![5.png](img/5.png)


<details>
<summary>Processed headers (85+ types)</summary>

- `X-forefront-antispam-report`
- `X-exchange-antispam`
- `X-exchange-antispam-mailbox-delivery`
- `X-exchange-antispam-message-info`
- `X-microsoft-antispam-report-cfa-test`
- `Received`, `From`, `To`, `Subject`, `Thread-topic`
- `Received-spf`
- `X-mailer`, `X-originating-ip`, `User-agent`
- `X-microsoft-antispam-mailbox-delivery`
- `X-microsoft-antispam`
- `X-spam-status`, `X-spam-level`, `X-spam-flag`, `X-spam-report`
- `X-vr-spamcause`, `X-ovh-spam-reason`, `X-vr-spamscore`
- `X-virus-scanned`, `X-spam-checker-version`
- `X-ironport-av`, `X-ironport-anti-spam-filtered`, `X-ironport-anti-spam-result`
- `X-mimecast-spam-score`
- `Spamdiagnosticmetadata`
- `X-ms-exchange-atpmessageproperties`
- `X-msfbl`
- `X-ms-exchange-transport-endtoendlatency`
- `X-ms-oob-tlc-oobclassifiers`
- `X-ip-spam-verdict`, `X-amp-result`
- `X-ironport-remoteip`, `X-ironport-reputation`, `X-sbrs`
- `X-ironport-sendergroup`, `X-policy`, `X-ironport-mailflowpolicy`
- `X-sea-spam`, `X-fireeye`, `X-antiabuse`
- `X-tmase-version`, `X-tm-as-product-ver`, `X-tm-as-result`
- `X-imss-scan-details`, `X-tm-as-user-approved-sender`, `X-tm-as-user-blocked-sender`
- `X-tmase-result`, `X-tmase-snap-result`, `X-imss-dkim-white-list`
- `X-scanned-by`, `X-mimecast-spam-signature`, `X-mimecast-bulk-signature`
- `X-sender-ip`, `X-forefront-antispam-report-untrusted`
- `X-sophos-senderhistory`, `X-sophos-rescan`
- `X-MS-Exchange-CrossTenant-Id`, `X-OriginatorOrg`
- `IronPort-Data`, `IronPort-HdrOrdr`
- `X-DKIM`, `DKIM-Filter`
- `X-SpamExperts-Class`, `X-SpamExperts-Evidence`
- `X-Recommended-Action`, `X-AppInfo`, `X-Spam`
- `X-TM-AS-MatchedID`
- `X-MS-Exchange-EnableFirstContactSafetyTip`
- `X-MS-Exchange-Organization-BypassFocusedInbox`
- `X-MS-Exchange-SkipListedInternetSender`
- `X-MS-Exchange-ExternalOriginalInternetSender`
- `X-CNFS-Analysis`, `X-Authenticated-Sender`
- `X-Apparently-From`, `X-Env-Sender`, `Sender`
- ...and more

</details>


## Credits

- **Analysis engine**: [decode-spam-headers.py](https://github.com/mgeeky/decode-spam-headers) by [Mariusz Banach / @mariuszbit](https://twitter.com/mariuszbit)
- **Web interface**: [Platima Tinkers](https://github.com/Platima) ([SBC Shop](https://shop.plati.ma) | [YouTube](https://youtube.com/@PlatimaTinkers))
- [ipSlav](https://github.com/ipSlav) for [identifying Office365 opaque rules](https://github.com/mgeeky/decode-spam-headers/issues/15)


## Known Issues

- `getOffice365TenantNameById(tenantID)` is not yet finished upstream
- `Authentication-Results` header is not yet completely parsed upstream


## Licence

[MIT](LICENSE) - Copyright 2021 Mariusz Banach, 2025 Platima Tinkers

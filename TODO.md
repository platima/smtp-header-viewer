1. COPILOT.md will need updating; the site should use solarized colour theme (dark), semver, and Australian English with no double hyphens (--) or em dashes. Git commits should be done after each change, push after each complete set for release.
2. I have updated just the first two lines of README.md but the rest would need an update to account for these changes, eg the URL, purpose, etc. I'll have to take new screenshots too.
3. The crude changes to his python script should be made more compatible, so it works for this purpose, but can be merged back upstream without breaking his project. Eg make them conditional on how the script is called or something.
4. correlate-rules.py may no longer be required, to be confirmed, but likely best left if it's a fork of his? Else if I can merge the main .py changes without merging that delete it would work
5. Same goes for requirements.txt
6. Any obvious bugs should be fixed up
7. There probably needs to be some sort of rate limiting
8. A full security review is required to make sure that there's no ways this can be used to breach the hosting server
9. Any obvious improvements should be noted too.
10. I'll have Cloudflare WAF in front of this, so any considerations for that should be noted. I'll likely have caching bypassed if required.
11. Use a nicer set of fonts, maybe Intel Mono One for anything fixed-width, and something similar for the rest.
12. Support dark & light mode, defaulting to user system config.
13. Credit Platima Tinkers (SBC Shop: https://shop.plati.ma, YouTube: https://youtube.com/@PlatimaTinkers, GitHub: https://github.com/Platima) somewhere, eg footer
14. Maybe track some metrics somehow/somewhere if it's worth it
15. Setup a full test suite
# Disclaimer & scope

This repository is **security research and educational documentation** about how a commercial mobile
request-signing / VMP protection stack is structured, and how it can be reproduced offline for analysis.

**Explicitly out of scope:** content protection / DRM / media decryption. This repo is about *request signing*
(`X-Argus` & friends) only. Nothing here concerns decrypting or downloading protected media.

**What is NOT in this repository, by design:**

- **No ByteDance/Douyin proprietary binaries.** No `.apk`, `.so`, `.dex`, or decompiled proprietary source is
  redistributed. Reproduction requires your own extraction from a copy of the app you are entitled to analyze.
- **No live credential.** The hardcoded metasec license is redacted to a placeholder; the docs note where it
  lives in the app so a researcher can extract their own. It is a static constant present in every shipped copy
  of the binary — this repo simply does not reprint it.
- **No validated bypass.** The offline-signing harness emits a *well-formed but unvalidated* signature; it is
  explicitly **not** confirmed accepted by any server, and no attempt is made to build an API client, scraper,
  or automation tool on top of it.

**Intended use:** understanding VMP / anti-tamper / request-signing architecture and binary-analysis technique.
It is not intended to facilitate service abuse, rate-limit evasion, scraping, or any violation of ByteDance's
Terms of Service. Trademarks and code belong to their respective owners; analysis is presented under research /
fair-use norms. Rights-holder concerns: open an issue.

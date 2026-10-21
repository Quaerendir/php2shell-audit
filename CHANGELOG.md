# Changelog

All notable changes to `php2shell-audit` are documented here.

## [1.0.0] — 2026-10-22

### Added
- First release. Read-only audit for PHP2Shell (CVE-2026-109618, CVE-2026-109619): PHP engine use-after-free across requests, unauthenticated RCE.
- Discovery of every PHP build in the usual prefixes: distro, Sury, Remi, cPanel EA, CloudLinux alt-php, Plesk, LiteSpeed, FrankenPHP and shared-hosting `php-cgiNN`/`php.binNN`; `--php` for others.
- Per-build fix detection: package changelog (CVE IDs or "php2shell") first, then the distro matrix as of 2026-10-21 (Debian 13/12, Ubuntu 22.04/24.04/26.04), then upstream thresholds 8.5.12, 8.4.27, 8.3.36, 8.2.35. Distro builds without a readable changelog stay UNKNOWN.
- Web exposure from the SAPI and Apache `LoadModule` lines; unfixed CLI-only builds give MITIGATED.
- Interim settings per build and per FPM pool, web root scan (per-dir overrides, PHP in uploads, web-shell patterns), log and process IoC hunt. Interim settings never change the verdict.
- Works without root (shared hosting); avoids process substitution, which such hosts often deny.
- Same hardening as the sibling audits: pinned `PATH`, `#!/bin/bash`, os-release parsed as text, test hooks ignored for root; as root it refuses to run non-root-owned or writable PHP binaries.
- 55 regression tests and ShellCheck in CI; every verdict-relevant branch is mutation-tested.
